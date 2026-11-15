// SPDX-License-Identifier: GPL-2.0-or-later
#include <linux/bits.h>
#include <linux/bitfield.h>
#include <linux/clk.h>
#include <linux/completion.h>
#include <linux/delay.h>
#include <linux/gpio/consumer.h>
#include <linux/i2c.h>
#include <linux/io.h>
#include <linux/interrupt.h>
#include <linux/iopoll.h>
#include <linux/jiffies.h>
#include <linux/math64.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/pinctrl/consumer.h>
#include <linux/platform_device.h>
#include <linux/spinlock.h>

#define BIW_CFG			0x00
#define BIW_CTRL		0x04
#define BIW_TXR			0x08
#define BIW_RXR			0x0c
#define BIW_ACK			0x10
#define BIW_IE0			0x14
#define BIW_INT0		0x18
#define BIW_IE1			0x1c
#define BIW_INT1		0x20

#define BIW_CFG_CORE_EN		BIT(0)
#define BIW_CFG_SOFT_RESET	BIT(1)
#define BIW_CFG_PRER		GENMASK(31, 16)

#define BIW_CTRL_DONE		BIT(0)
#define BIW_CTRL_NACK		BIT(3)
#define BIW_CTRL_WRITE		BIT(4)
#define BIW_CTRL_READ		BIT(5)
#define BIW_CTRL_STOP		BIT(6)
#define BIW_CTRL_START		BIT(7)

#define BIW_ACK_AL		BIT(0)
#define BIW_ACK_BUSY		BIT(1)
#define BIW_ACK_NACK		BIT(2)

#define BIW_IRQ			BIT(0)

#define RTL9617C_I2C_TIMEOUT_MS		1000
#define RTL9617C_I2C_BUSY_TIMEOUT_US	100000
#define RTL9617C_I2C_POLL_US		10
#define RTL9617C_I2C_RECOVERY_US	5
#define RTL9617C_I2C_RECOVERY_CLOCKS	9

struct rtl9617c_i2c {
	void __iomem *base;
	struct device *dev;
	struct i2c_adapter adapter;
	struct i2c_bus_recovery_info recovery;
	struct completion completion;
	spinlock_t lock;
	struct i2c_msg *msgs;
	int num;
	int cur;
	int pos;
	int error;
	int irq;
	bool active;
	bool addr_phase;
	bool ack_check;
	u32 prer;
	struct pinctrl *pinctrl;
	struct pinctrl_state *pins_default;
	struct pinctrl_state *pins_gpio;
};

static void rtl9617c_i2c_hw_init(struct rtl9617c_i2c *i2c)
{
	writel(BIW_CFG_SOFT_RESET, i2c->base + BIW_CFG);
	mdelay(10);
	writel(FIELD_PREP(BIW_CFG_PRER, i2c->prer) | BIW_CFG_CORE_EN,
	       i2c->base + BIW_CFG);
	writel(0, i2c->base + BIW_IE0);
	writel(BIW_IRQ, i2c->base + BIW_INT0);
	writel(0, i2c->base + BIW_IE1);
	writel(BIW_IRQ, i2c->base + BIW_INT1);
}

static void rtl9617c_i2c_enable(struct rtl9617c_i2c *i2c)
{
	writel(BIW_IRQ, i2c->base + BIW_IE0);
}

static void rtl9617c_i2c_issue_addr(struct rtl9617c_i2c *i2c)
{
	struct i2c_msg *msg = &i2c->msgs[i2c->cur];
	u32 ctrl = BIW_CTRL_START | BIW_CTRL_WRITE;

	if (!msg->len && i2c->cur == i2c->num - 1)
		ctrl |= BIW_CTRL_STOP;
	writel(i2c_8bit_addr_from_msg(msg), i2c->base + BIW_TXR);
	i2c->addr_phase = true;
	i2c->ack_check = true;
	writel(ctrl, i2c->base + BIW_CTRL);
}

static void rtl9617c_i2c_issue_data(struct rtl9617c_i2c *i2c)
{
	struct i2c_msg *msg = &i2c->msgs[i2c->cur];
	bool read = msg->flags & I2C_M_RD;
	bool last = i2c->pos == msg->len - 1;
	u32 ctrl = read ? BIW_CTRL_READ : BIW_CTRL_WRITE;

	if (read && last)
		ctrl |= BIW_CTRL_NACK;
	if (last && i2c->cur == i2c->num - 1)
		ctrl |= BIW_CTRL_STOP;
	if (!read)
		writel(msg->buf[i2c->pos], i2c->base + BIW_TXR);
	i2c->addr_phase = false;
	i2c->ack_check = !read;
	writel(ctrl, i2c->base + BIW_CTRL);
}

static void rtl9617c_i2c_finish(struct rtl9617c_i2c *i2c, int error)
{
	i2c->error = error;
	i2c->active = false;
	complete(&i2c->completion);
}

static void rtl9617c_i2c_next_msg(struct rtl9617c_i2c *i2c)
{
	if (++i2c->cur == i2c->num) {
		rtl9617c_i2c_finish(i2c, 0);
		return;
	}
	i2c->pos = 0;
	rtl9617c_i2c_issue_addr(i2c);
}

static void rtl9617c_i2c_step(struct rtl9617c_i2c *i2c, u32 ack)
{
	struct i2c_msg *msg = &i2c->msgs[i2c->cur];

	if (ack & BIW_ACK_AL) {
		rtl9617c_i2c_finish(i2c, -EAGAIN);
		return;
	}
	if (i2c->ack_check && (ack & BIW_ACK_NACK)) {
		rtl9617c_i2c_finish(i2c, -ENXIO);
		return;
	}
	if (i2c->addr_phase) {
		if (!msg->len) {
			rtl9617c_i2c_next_msg(i2c);
			return;
		}
		i2c->pos = 0;
		rtl9617c_i2c_issue_data(i2c);
		return;
	}
	if (msg->flags & I2C_M_RD)
		msg->buf[i2c->pos] = readl(i2c->base + BIW_RXR);
	if (++i2c->pos < msg->len) {
		rtl9617c_i2c_issue_data(i2c);
		return;
	}
	rtl9617c_i2c_next_msg(i2c);
}

static irqreturn_t rtl9617c_i2c_irq(int irq, void *dev_id)
{
	struct rtl9617c_i2c *i2c = dev_id;
	unsigned long flags;
	u32 ctrl, ack;

	spin_lock_irqsave(&i2c->lock, flags);
	ctrl = readl(i2c->base + BIW_CTRL);
	writel(ctrl, i2c->base + BIW_CTRL);
	writel(BIW_IRQ, i2c->base + BIW_INT0);
	if (!i2c->active || !(ctrl & BIW_CTRL_DONE)) {
		spin_unlock_irqrestore(&i2c->lock, flags);
		return IRQ_HANDLED;
	}
	ack = readl(i2c->base + BIW_ACK);
	rtl9617c_i2c_step(i2c, ack);
	spin_unlock_irqrestore(&i2c->lock, flags);
	return IRQ_HANDLED;
}

static void rtl9617c_i2c_abort(struct rtl9617c_i2c *i2c)
{
	unsigned long flags;

	spin_lock_irqsave(&i2c->lock, flags);
	i2c->active = false;
	writel(0, i2c->base + BIW_IE0);
	spin_unlock_irqrestore(&i2c->lock, flags);
	synchronize_irq(i2c->irq);
	rtl9617c_i2c_hw_init(i2c);
}

static void rtl9617c_i2c_stop(struct rtl9617c_i2c *i2c)
{
	u32 value;
	int ret;

	writel(BIW_CTRL_STOP, i2c->base + BIW_CTRL);
	ret = readl_poll_timeout(i2c->base + BIW_CTRL, value,
				 value & BIW_CTRL_DONE,
				 RTL9617C_I2C_POLL_US, 10000);
	if (ret) {
		rtl9617c_i2c_hw_init(i2c);
		return;
	}
	writel(value, i2c->base + BIW_CTRL);
	writel(BIW_IRQ, i2c->base + BIW_INT0);
}

static void rtl9617c_i2c_scl_set(struct gpio_desc *scl, int value)
{
	if (value)
		gpiod_direction_input(scl);
	else
		gpiod_direction_output(scl, 0);
}

static int rtl9617c_i2c_recover_bus(struct i2c_adapter *adap)
{
	struct rtl9617c_i2c *i2c = i2c_get_adapdata(adap);
	struct gpio_desc *scl, *sda = NULL;
	int ret, restore_ret, i;

	ret = pinctrl_select_state(i2c->pinctrl, i2c->pins_gpio);
	if (ret)
		return ret;

	scl = gpiod_get_optional(i2c->dev, "scl", GPIOD_IN);
	if (IS_ERR(scl)) {
		ret = PTR_ERR(scl);
		goto restore;
	}
	if (!scl) {
		ret = -EOPNOTSUPP;
		goto restore;
	}

	sda = gpiod_get_optional(i2c->dev, "sda", GPIOD_IN);
	if (IS_ERR(sda))
		sda = NULL;

	for (i = 0; i < RTL9617C_I2C_RECOVERY_CLOCKS; i++) {
		rtl9617c_i2c_scl_set(scl, 0);
		udelay(RTL9617C_I2C_RECOVERY_US);
		rtl9617c_i2c_scl_set(scl, 1);
		udelay(RTL9617C_I2C_RECOVERY_US);
	}

	if (!gpiod_get_value_cansleep(scl)) {
		ret = -EBUSY;
		goto put_sda;
	}

	if (sda) {
		rtl9617c_i2c_scl_set(scl, 0);
		gpiod_direction_output(sda, 0);
		udelay(RTL9617C_I2C_RECOVERY_US);
		rtl9617c_i2c_scl_set(scl, 1);
		udelay(RTL9617C_I2C_RECOVERY_US);
		gpiod_direction_input(sda);
		udelay(RTL9617C_I2C_RECOVERY_US);
	}
	ret = 0;

put_sda:
	if (sda)
		gpiod_put(sda);
	gpiod_put(scl);
restore:
	restore_ret = pinctrl_select_state(i2c->pinctrl, i2c->pins_default);
	if (!ret)
		ret = restore_ret;
	return ret;
}

static int rtl9617c_i2c_xfer(struct i2c_adapter *adap, struct i2c_msg *msgs,
			     int num)
{
	struct rtl9617c_i2c *i2c = i2c_get_adapdata(adap);
	unsigned long flags, time_left;
	u32 value;
	int i, ret;

	if (!num)
		return -EINVAL;

	for (i = 0; i < num; i++) {
		if (msgs[i].flags & ~(I2C_M_RD | I2C_M_DMA_SAFE))
			return -EOPNOTSUPP;
	}

	ret = readl_poll_timeout(i2c->base + BIW_ACK, value,
				 !(value & BIW_ACK_BUSY),
				 RTL9617C_I2C_POLL_US,
				 RTL9617C_I2C_BUSY_TIMEOUT_US);
	if (ret) {
		rtl9617c_i2c_abort(i2c);
		if (i2c->adapter.bus_recovery_info)
			i2c_recover_bus(adap);
		rtl9617c_i2c_enable(i2c);
		return -EBUSY;
	}

	spin_lock_irqsave(&i2c->lock, flags);
	i2c->msgs = msgs;
	i2c->num = num;
	i2c->cur = 0;
	i2c->pos = 0;
	i2c->error = 0;
	i2c->active = true;
	reinit_completion(&i2c->completion);
	rtl9617c_i2c_issue_addr(i2c);
	spin_unlock_irqrestore(&i2c->lock, flags);

	time_left = wait_for_completion_timeout(&i2c->completion,
						msecs_to_jiffies(RTL9617C_I2C_TIMEOUT_MS));
	if (!time_left) {
		rtl9617c_i2c_abort(i2c);
		if (i2c->adapter.bus_recovery_info &&
		    i2c_recover_bus(adap))
			dev_warn(i2c->dev, "bus recovery failed\n");
		rtl9617c_i2c_enable(i2c);
		return -ETIMEDOUT;
	}

	if (i2c->error == -EAGAIN) {
		rtl9617c_i2c_abort(i2c);
		rtl9617c_i2c_enable(i2c);
		return i2c->error;
	}

	if (i2c->error) {
		spin_lock_irqsave(&i2c->lock, flags);
		writel(0, i2c->base + BIW_IE0);
		spin_unlock_irqrestore(&i2c->lock, flags);
		synchronize_irq(i2c->irq);
		rtl9617c_i2c_stop(i2c);
		rtl9617c_i2c_enable(i2c);
		return i2c->error;
	}

	return num;
}

static u32 rtl9617c_i2c_functionality(struct i2c_adapter *adap)
{
	return I2C_FUNC_I2C | I2C_FUNC_SMBUS_BYTE |
	       I2C_FUNC_SMBUS_BYTE_DATA | I2C_FUNC_SMBUS_WORD_DATA |
	       I2C_FUNC_SMBUS_I2C_BLOCK;
}

static const struct i2c_algorithm rtl9617c_i2c_algorithm = {
	.xfer = rtl9617c_i2c_xfer,
	.functionality = rtl9617c_i2c_functionality,
};

static int rtl9617c_i2c_recovery_init(struct rtl9617c_i2c *i2c)
{
	struct device *dev = i2c->dev;
	int ret;

	if (!device_property_present(dev, "scl-gpios"))
		return 0;

	i2c->pinctrl = devm_pinctrl_get(dev);
	if (IS_ERR(i2c->pinctrl)) {
		ret = PTR_ERR(i2c->pinctrl);
		i2c->pinctrl = NULL;
		return ret == -ENODEV ? 0 : ret;
	}

	i2c->pins_default = pinctrl_lookup_state(i2c->pinctrl, "default");
	if (IS_ERR(i2c->pins_default)) {
		i2c->pins_default = NULL;
		goto no_recovery;
	}

	i2c->pins_gpio = pinctrl_lookup_state(i2c->pinctrl, "gpio");
	if (IS_ERR(i2c->pins_gpio)) {
		i2c->pins_gpio = NULL;
		goto no_recovery;
	}

	i2c->recovery.recover_bus = rtl9617c_i2c_recover_bus;
	i2c->adapter.bus_recovery_info = &i2c->recovery;
	return 0;

no_recovery:
	dev_warn(dev, "bus recovery disabled\n");
	return 0;
}

static void rtl9617c_i2c_disable(void *data)
{
	struct rtl9617c_i2c *i2c = data;
	unsigned long flags;

	spin_lock_irqsave(&i2c->lock, flags);
	i2c->active = false;
	writel(0, i2c->base + BIW_IE0);
	spin_unlock_irqrestore(&i2c->lock, flags);
	synchronize_irq(i2c->irq);
	writel(0, i2c->base + BIW_CFG);
}

static int rtl9617c_i2c_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct rtl9617c_i2c *i2c;
	struct clk *clk;
	unsigned long rate;
	u64 div, scl;
	u32 frequency = 100000;
	int ret;

	i2c = devm_kzalloc(dev, sizeof(*i2c), GFP_KERNEL);
	if (!i2c)
		return -ENOMEM;
	i2c->dev = dev;
	i2c->base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(i2c->base))
		return PTR_ERR(i2c->base);

	i2c->adapter.owner = THIS_MODULE;
	i2c->adapter.algo = &rtl9617c_i2c_algorithm;
	i2c->adapter.dev.parent = dev;
	i2c->adapter.dev.of_node = dev->of_node;
	strscpy(i2c->adapter.name, "rtl9617c-i2c", sizeof(i2c->adapter.name));
	i2c_set_adapdata(&i2c->adapter, i2c);

	clk = devm_clk_get_enabled(dev, NULL);
	if (IS_ERR(clk))
		return dev_err_probe(dev, PTR_ERR(clk),
				     "failed to enable clock\n");

	rate = clk_get_rate(clk);
	if (!rate)
		return dev_err_probe(dev, -EINVAL, "invalid clock rate\n");
	device_property_read_u32(dev, "clock-frequency", &frequency);
	if (!frequency)
		return dev_err_probe(dev, -EINVAL, "invalid clock-frequency\n");
	div = DIV_ROUND_UP_ULL(rate, 5ULL * frequency);
	if (!div || div > 65536)
		return dev_err_probe(dev, -EINVAL,
				     "unsupported clock-frequency %u\n",
				     frequency);
	i2c->prer = div - 1;
	scl = rate / (5 * div);

	init_completion(&i2c->completion);
	spin_lock_init(&i2c->lock);

	ret = rtl9617c_i2c_recovery_init(i2c);
	if (ret)
		return ret;

	i2c->irq = platform_get_irq(pdev, 0);
	if (i2c->irq < 0)
		return i2c->irq;

	rtl9617c_i2c_hw_init(i2c);
	ret = devm_request_irq(dev, i2c->irq, rtl9617c_i2c_irq, 0,
			       dev_name(dev), i2c);
	if (ret)
		return ret;
	rtl9617c_i2c_enable(i2c);
	ret = devm_add_action_or_reset(dev, rtl9617c_i2c_disable, i2c);
	if (ret)
		return ret;

	platform_set_drvdata(pdev, i2c);
	dev_info(dev, "irq %d, SCL %llu Hz, APB %lu Hz, prescale %u\n",
		 i2c->irq, scl, rate, i2c->prer);
	return devm_i2c_add_adapter(dev, &i2c->adapter);
}

static const struct of_device_id rtl9617c_i2c_match[] = {
	{ .compatible = "realtek,rtl9617c-i2c" },
	{ }
};
MODULE_DEVICE_TABLE(of, rtl9617c_i2c_match);

static struct platform_driver rtl9617c_i2c_driver = {
	.probe = rtl9617c_i2c_probe,
	.driver = {
		.name = "rtl9617c-i2c",
		.of_match_table = rtl9617c_i2c_match,
	},
};
module_platform_driver(rtl9617c_i2c_driver);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("RTL9617C BIW I2C controller");
