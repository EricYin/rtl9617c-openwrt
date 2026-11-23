// SPDX-License-Identifier: GPL-2.0

#include <linux/bitfield.h>
#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/gpio/consumer.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/irq.h>
#include <linux/irqdomain.h>
#include <linux/of.h>
#include <linux/phy/phy.h>
#include <linux/platform_device.h>
#include <linux/reset.h>
#include <linux/soc/realtek/taurus-soc.h>
#include <linux/spinlock.h>

#include "pcie-designware.h"

#define MAX_LANES			2

#define GLB_INTR_STATUS			0x00
#define GLB_INTR_ENABLE			0x04
#define  INTR_INTX_ASSERT(n)		BIT(2 * (n))
#define  INTR_MSI			BIT(8)
#define  INTR_LINK_DOWN			BIT(22)
#define  INTR_MISC_MASK			(GENMASK(16, 10) | GENMASK(27, 23))
#define GLB_CORE_CONFIG			0x18
#define  CORE_LTSSM_ENABLE		BIT(0)
#define  CORE_LINK_DOWN_RST		BIT(6)
#define GLB_PM_STATUS			0x1c
#define  PM_LTSSM_STATE			GENMASK(9, 4)
#define  PM_RDLH_LINK_UP		BIT(18)
#define GLB_DBI_START			0x40
#define GLB_DBI_END			0x44
#define GLB_IATU_BASE			0x48
#define  IATU_BASE_MASK			GENMASK(31, 19)
#define GLB_MSI_ENABLE			0x1a4

#define SERDES_LANE_STRIDE		0x1000
#define SERDES_SUBBLOCK_STRIDE		0x100
#define SERDES_CAL_STATUS		0x7c
#define  SERDES_CAL_DONE		BIT(4)
#define  SERDES_BER_READY		BIT(0)

struct taurus_pcie {
	struct dw_pcie pci;
	void __iomem *glb;
	void __iomem *serdes;
	resource_size_t serdes_size;
	struct reset_control *core_rst;
	struct reset_control *phy_rst;
	struct gpio_desc *perst;
	struct phy *phy[MAX_LANES];
	struct irq_domain *intx_domain;
	u32 *serdes_cfg;
	int serdes_cfg_cnt;
	raw_spinlock_t intr_lock;
	u32 idx;
	u32 lanes;
	bool rev_a;
	bool phy_on;
};

#define to_taurus_pcie(x)	container_of(x, struct taurus_pcie, pci)

static const char * const ltssm_names[] = {
	"DETECT_QUIET", "DETECT_ACT", "POLL_ACTIVE", "POLL_COMPLIANCE",
	"POLL_CONFIG", "PRE_DETECT_QUIET", "DETECT_WAIT", "CFG_LINKWD_START",
	"CFG_LINKWD_ACEPT", "CFG_LANENUM_WAI", "CFG_LANENUM_ACEPT",
	"CFG_COMPLETE", "CFG_IDLE", "RCVRY_LOCK", "RCVRY_SPEED",
	"RCVRY_RCVRCFG", "RCVRY_IDLE", "L0", "L0S", "L123_SEND_EIDLE",
	"L1_IDLE", "L2_IDLE", "L2_WAKE", "DISABLED_ENTRY", "DISABLED_IDLE",
	"DISABLED", "LPBK_ENTRY", "LPBK_ACTIVE", "LPBK_EXIT",
	"LPBK_EXIT_TIMEOUT", "HOT_RESET_ENTRY", "HOT_RESET", "RCVRY_EQ0",
	"RCVRY_EQ1", "RCVRY_EQ2", "RCVRY_EQ3",
};

static u32 glb_read(struct taurus_pcie *pcie, u32 reg)
{
	return readl(pcie->glb + reg);
}

static void glb_write(struct taurus_pcie *pcie, u32 val, u32 reg)
{
	writel(val, pcie->glb + reg);
}

static void taurus_pcie_intr_update(struct taurus_pcie *pcie, u32 clr, u32 set)
{
	unsigned long flags;
	u32 val;

	raw_spin_lock_irqsave(&pcie->intr_lock, flags);
	val = glb_read(pcie, GLB_INTR_ENABLE);
	val &= ~clr;
	val |= set;
	glb_write(pcie, val, GLB_INTR_ENABLE);
	raw_spin_unlock_irqrestore(&pcie->intr_lock, flags);
}

static u32 taurus_pcie_ltssm(struct taurus_pcie *pcie)
{
	return FIELD_GET(PM_LTSSM_STATE, glb_read(pcie, GLB_PM_STATUS));
}

static const char *taurus_pcie_ltssm_name(u32 state)
{
	return state < ARRAY_SIZE(ltssm_names) ? ltssm_names[state] : "UNKNOWN";
}

static void taurus_intx_mask(struct irq_data *d)
{
	struct taurus_pcie *pcie = irq_data_get_irq_chip_data(d);

	taurus_pcie_intr_update(pcie, INTR_INTX_ASSERT(d->hwirq), 0);
}

static void taurus_intx_unmask(struct irq_data *d)
{
	struct taurus_pcie *pcie = irq_data_get_irq_chip_data(d);

	taurus_pcie_intr_update(pcie, 0, INTR_INTX_ASSERT(d->hwirq));
}

static struct irq_chip taurus_intx_chip = {
	.name		= "Taurus PCIe INTx",
	.irq_mask	= taurus_intx_mask,
	.irq_unmask	= taurus_intx_unmask,
};

static int taurus_intx_map(struct irq_domain *domain, unsigned int irq,
			   irq_hw_number_t hwirq)
{
	irq_set_chip_and_handler(irq, &taurus_intx_chip, handle_simple_irq);
	irq_set_chip_data(irq, domain->host_data);

	return 0;
}

static const struct irq_domain_ops taurus_intx_domain_ops = {
	.map	= taurus_intx_map,
	.xlate	= irq_domain_xlate_onecell,
};

static irqreturn_t taurus_pcie_irq_handler(int irq, void *data)
{
	struct taurus_pcie *pcie = data;
	struct dw_pcie_rp *pp = &pcie->pci.pp;
	u32 status = glb_read(pcie, GLB_INTR_STATUS);
	unsigned int i;

	if (!status)
		return IRQ_NONE;

	if (status & INTR_MSI)
		dw_handle_msi_irq(pp);

	for (i = 0; i < PCI_NUM_INTX; i++) {
		if (status & INTR_INTX_ASSERT(i))
			generic_handle_domain_irq(pcie->intx_domain, i);
	}

	if (status & INTR_LINK_DOWN) {
		u32 state = taurus_pcie_ltssm(pcie);

		dev_err(pcie->pci.dev, "link down, LTSSM state %s\n",
			taurus_pcie_ltssm_name(state));
		glb_write(pcie, CORE_LINK_DOWN_RST, GLB_CORE_CONFIG);
	}

	glb_write(pcie, status, GLB_INTR_STATUS);

	return IRQ_HANDLED;
}

static void serdes_write(struct taurus_pcie *pcie, unsigned int lane, u32 off,
			 u32 val)
{
	writel(val, pcie->serdes + lane * SERDES_LANE_STRIDE + off);
	usleep_range(10, 20);
}

static void serdes_update(struct taurus_pcie *pcie, unsigned int lane, u32 off,
			  u32 mask, u32 val)
{
	void __iomem *reg = pcie->serdes + lane * SERDES_LANE_STRIDE + off;
	u32 tmp = readl(reg);

	tmp &= ~mask;
	tmp |= val;
	writel(tmp, reg);
	usleep_range(10, 20);
}

static void serdes_update_lane_blocks(struct taurus_pcie *pcie,
				      unsigned int lane, u32 off, u32 mask,
				      u32 val)
{
	serdes_update(pcie, lane, off, mask, val);
	serdes_update(pcie, lane, off + SERDES_SUBBLOCK_STRIDE, mask, val);
}

static void serdes_update_blocks(struct taurus_pcie *pcie, u32 off, u32 mask,
				 u32 val)
{
	unsigned int lane;

	for (lane = 0; lane < pcie->lanes; lane++)
		serdes_update_lane_blocks(pcie, lane, off, mask, val);
}

static void serdes_write_blocks(struct taurus_pcie *pcie, u32 off, u32 val)
{
	unsigned int lane;

	for (lane = 0; lane < pcie->lanes; lane++) {
		serdes_write(pcie, lane, off, val);
		serdes_write(pcie, lane, off + SERDES_SUBBLOCK_STRIDE, val);
	}
}

static void serdes_toggle(struct taurus_pcie *pcie, u32 first, u32 second)
{
	unsigned int lane;

	for (lane = 0; lane < pcie->lanes; lane++) {
		serdes_write(pcie, lane, 0x24, first);
		serdes_write(pcie, lane, 0x24, second);
		serdes_write(pcie, lane, 0x124, first);
		serdes_write(pcie, lane, 0x124, second);
	}
}

static int serdes_wait_cal_done(struct taurus_pcie *pcie)
{
	u32 val;
	int ret;

	ret = readl_poll_timeout(pcie->serdes + SERDES_CAL_STATUS, val,
				 val & SERDES_CAL_DONE, 10, 100000);
	if (ret)
		dev_err(pcie->pci.dev, "SerDes calibration timed out\n");

	return ret;
}

static void serdes_load_cfg(struct taurus_pcie *pcie)
{
	unsigned int lane;
	int i;

	for (lane = 0; lane < pcie->lanes; lane++) {
		for (i = 0; i < pcie->serdes_cfg_cnt; i++) {
			u32 off = pcie->serdes_cfg[2 * i] +
				  lane * SERDES_LANE_STRIDE;

			if (off < pcie->serdes_size)
				writel(pcie->serdes_cfg[2 * i + 1],
				       pcie->serdes + off);
		}
	}
}

static bool serdes_ber_ready(struct taurus_pcie *pcie)
{
	u32 val = readl(pcie->serdes + 0x7c) & readl(pcie->serdes + 0x17c);

	if (pcie->lanes == 2)
		val &= readl(pcie->serdes + 0x107c) &
		       readl(pcie->serdes + 0x117c);

	return val & SERDES_BER_READY;
}

static int taurus_pcie_phy_power_on(struct taurus_pcie *pcie)
{
	unsigned int i;
	int ret;

	for (i = 0; i < pcie->lanes; i++) {
		ret = phy_power_on(pcie->phy[i]);
		if (ret)
			goto err_off;
	}
	pcie->phy_on = true;

	return 0;

err_off:
	while (i--)
		phy_power_off(pcie->phy[i]);

	return ret;
}

static void taurus_pcie_phy_power_off(struct taurus_pcie *pcie)
{
	unsigned int i;

	if (!pcie->phy_on)
		return;

	for (i = 0; i < pcie->lanes; i++)
		phy_power_off(pcie->phy[i]);
	pcie->phy_on = false;
}

static int serdes_restart(struct taurus_pcie *pcie)
{
	int ret;

	taurus_pcie_phy_power_off(pcie);
	usleep_range(1000, 2000);

	reset_control_assert(pcie->phy_rst);
	usleep_range(1000, 2000);
	reset_control_assert(pcie->core_rst);
	usleep_range(1000, 2000);

	ret = taurus_pcie_phy_power_on(pcie);
	if (ret)
		return ret;
	usleep_range(1000, 2000);

	reset_control_deassert(pcie->phy_rst);
	usleep_range(1000, 2000);
	reset_control_deassert(pcie->core_rst);
	usleep_range(1000, 2000);

	return 0;
}

static int serdes_calibrate(struct taurus_pcie *pcie)
{
	void __iomem *base = pcie->serdes;
	u32 val;
	int ret;

	if (pcie->idx != 0)
		return 0;

	serdes_toggle(pcie, 0x500c, 0x520c);
	serdes_update_blocks(pcie, 0x34, BIT(6), BIT(6));
	serdes_update_blocks(pcie, 0x08, BIT(9), BIT(9));
	serdes_write_blocks(pcie, 0x40, 0x194);
	serdes_update_blocks(pcie, 0xbc, BIT(10), BIT(10));
	serdes_update_blocks(pcie, 0x6c, GENMASK(6, 5), 0);

	ret = serdes_wait_cal_done(pcie);
	if (ret)
		return ret;

	if (pcie->lanes == 2) {
		serdes_update_blocks(pcie, 0x6c, GENMASK(6, 5), BIT(5));

		ret = serdes_wait_cal_done(pcie);
		if (ret)
			return ret;
	}

	serdes_update_blocks(pcie, 0x08, BIT(9), 0);
	serdes_update_blocks(pcie, 0x6c, GENMASK(6, 5), 0);
	serdes_write_blocks(pcie, 0x40, 0x1a4);

	val = FIELD_GET(GENMASK(4, 0), readl(base + SERDES_CAL_STATUS));
	serdes_update_lane_blocks(pcie, 0, 0x0c, GENMASK(5, 1),
				  FIELD_PREP(GENMASK(5, 1), val));

	if (pcie->lanes == 2) {
		serdes_update_blocks(pcie, 0x6c, GENMASK(6, 5), BIT(5));

		val = FIELD_GET(GENMASK(4, 0),
				readl(base + SERDES_CAL_STATUS));
		serdes_update_lane_blocks(pcie, 1, 0x0c, GENMASK(5, 1),
					  FIELD_PREP(GENMASK(5, 1), val));
	}

	serdes_toggle(pcie, 0x501c, 0x521c);
	serdes_update_blocks(pcie, 0x34, BIT(6), 0);
	serdes_update_blocks(pcie, 0xbc, BIT(10), 0);
	serdes_update_blocks(pcie, 0x6c, GENMASK(6, 5), 0);
	serdes_write_blocks(pcie, 0x40, 0x0c);

	val = FIELD_GET(GENMASK(4, 1), readl(base + SERDES_CAL_STATUS));
	serdes_update_lane_blocks(pcie, 0, 0x2c, GENMASK(8, 5),
				  FIELD_PREP(GENMASK(8, 5), val));

	if (pcie->lanes == 2) {
		val = FIELD_GET(GENMASK(4, 1), readl(base + 0x107c));
		serdes_update_lane_blocks(pcie, 1, 0x2c, GENMASK(8, 5),
					  FIELD_PREP(GENMASK(8, 5), val));
	}

	serdes_update_blocks(pcie, 0x34, BIT(13), 0);

	return serdes_restart(pcie);
}

static int taurus_pcie_reset(struct taurus_pcie *pcie)
{
	struct device *dev = pcie->pci.dev;
	bool ready;
	int ret;

	gpiod_set_value_cansleep(pcie->perst, 1);

	reset_control_assert(pcie->core_rst);
	usleep_range(1000, 2000);
	reset_control_assert(pcie->phy_rst);
	usleep_range(1000, 2000);

	serdes_load_cfg(pcie);

	ret = taurus_pcie_phy_power_on(pcie);
	if (ret)
		return ret;
	usleep_range(1000, 2000);

	reset_control_deassert(pcie->phy_rst);
	usleep_range(1000, 2000);
	reset_control_deassert(pcie->core_rst);
	usleep_range(1000, 2000);

	if (pcie->rev_a)
		serdes_toggle(pcie, 0x500c, 0x520c);
	else
		ret = serdes_calibrate(pcie);
	if (ret) {
		taurus_pcie_phy_power_off(pcie);
		return ret;
	}

	ret = read_poll_timeout(serdes_ber_ready, ready, ready, 1000, 100000,
				false, pcie);
	if (ret)
		dev_warn(dev, "SerDes BER notification missing\n");

	msleep(PCIE_T_PVPERL_MS);
	gpiod_set_value_cansleep(pcie->perst, 0);

	return 0;
}

static void taurus_pcie_power_off(struct taurus_pcie *pcie)
{
	glb_write(pcie, 0, GLB_INTR_ENABLE);
	gpiod_set_value_cansleep(pcie->perst, 1);
	reset_control_assert(pcie->core_rst);
	reset_control_assert(pcie->phy_rst);
	taurus_pcie_phy_power_off(pcie);
}

static int taurus_pcie_host_init(struct dw_pcie_rp *pp)
{
	struct dw_pcie *pci = to_dw_pcie_from_pp(pp);
	struct taurus_pcie *pcie = to_taurus_pcie(pci);
	struct platform_device *pdev = to_platform_device(pci->dev);
	struct resource *dbi;
	int ret;

	ret = taurus_pcie_reset(pcie);
	if (ret) {
		taurus_pcie_power_off(pcie);
		return ret;
	}

	dbi = platform_get_resource_byname(pdev, IORESOURCE_MEM, "dbi");
	glb_write(pcie, dbi->start, GLB_DBI_START);
	glb_write(pcie, dbi->end, GLB_DBI_END);
	glb_write(pcie, pci->atu_phys_addr & IATU_BASE_MASK, GLB_IATU_BASE);

	glb_write(pcie, ~0, GLB_MSI_ENABLE);
	taurus_pcie_intr_update(pcie, 0, INTR_MISC_MASK | INTR_MSI);

	return 0;
}

static void taurus_pcie_host_deinit(struct dw_pcie_rp *pp)
{
	struct dw_pcie *pci = to_dw_pcie_from_pp(pp);

	taurus_pcie_power_off(to_taurus_pcie(pci));
}

static void taurus_pcie_host_post_init(struct dw_pcie_rp *pp)
{
	struct dw_pcie *pci = to_dw_pcie_from_pp(pp);
	struct taurus_pcie *pcie = to_taurus_pcie(pci);

	if (dw_pcie_link_up(pci)) {
		taurus_pcie_intr_update(pcie, 0, INTR_LINK_DOWN);
		return;
	}

	dev_warn(pci->dev, "link is down, LTSSM state %s\n",
		 taurus_pcie_ltssm_name(taurus_pcie_ltssm(pcie)));
}

static const struct dw_pcie_host_ops taurus_pcie_host_ops = {
	.init		= taurus_pcie_host_init,
	.deinit		= taurus_pcie_host_deinit,
	.post_init	= taurus_pcie_host_post_init,
};

static bool taurus_pcie_link_up(struct dw_pcie *pci)
{
	struct taurus_pcie *pcie = to_taurus_pcie(pci);

	return glb_read(pcie, GLB_PM_STATUS) & PM_RDLH_LINK_UP;
}

static int taurus_pcie_start_link(struct dw_pcie *pci)
{
	struct taurus_pcie *pcie = to_taurus_pcie(pci);

	glb_write(pcie, CORE_LTSSM_ENABLE, GLB_CORE_CONFIG);

	return 0;
}

static void taurus_pcie_stop_link(struct dw_pcie *pci)
{
	struct taurus_pcie *pcie = to_taurus_pcie(pci);

	glb_write(pcie, CORE_LINK_DOWN_RST, GLB_CORE_CONFIG);
	usleep_range(100, 200);
	glb_write(pcie, 0, GLB_CORE_CONFIG);
	usleep_range(100, 200);
}

static const struct dw_pcie_ops taurus_pcie_ops = {
	.link_up	= taurus_pcie_link_up,
	.start_link	= taurus_pcie_start_link,
	.stop_link	= taurus_pcie_stop_link,
};

static void taurus_intx_domain_remove(void *data)
{
	irq_domain_remove(data);
}

static int taurus_pcie_init_intx(struct taurus_pcie *pcie)
{
	struct device *dev = pcie->pci.dev;
	struct device_node *intc;

	intc = of_get_child_by_name(dev->of_node, "interrupt-controller");
	if (!intc)
		return dev_err_probe(dev, -ENODEV,
				     "missing interrupt-controller node\n");

	pcie->intx_domain = irq_domain_create_linear(of_fwnode_handle(intc),
						     PCI_NUM_INTX,
						     &taurus_intx_domain_ops,
						     pcie);
	of_node_put(intc);
	if (!pcie->intx_domain)
		return -ENOMEM;

	return devm_add_action_or_reset(dev, taurus_intx_domain_remove,
					pcie->intx_domain);
}

static int taurus_pcie_parse_serdes_cfg(struct taurus_pcie *pcie)
{
	struct device *dev = pcie->pci.dev;
	struct device_node *np = dev->of_node;
	const char *prop = pcie->rev_a ? "serdes-cfg-dataA" : "serdes-cfg-dataB";
	const char *ver = NULL;
	int count, ret;

	count = of_property_count_u32_elems(np, prop);
	if (count <= 0 || count % 2)
		return dev_err_probe(dev, -EINVAL, "invalid %s\n", prop);

	pcie->serdes_cfg = devm_kcalloc(dev, count, sizeof(u32), GFP_KERNEL);
	if (!pcie->serdes_cfg)
		return -ENOMEM;

	ret = of_property_read_u32_array(np, prop, pcie->serdes_cfg, count);
	if (ret)
		return ret;

	pcie->serdes_cfg_cnt = count / 2;

	of_property_read_string(np, pcie->rev_a ? "serdes-cfg-verA" :
						   "serdes-cfg-verB", &ver);
	dev_info(dev, "SerDes configuration %s\n", ver ?: "(unversioned)");

	return 0;
}

static int taurus_pcie_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct device_node *np = dev->of_node;
	struct taurus_pcie *pcie;
	struct dw_pcie *pci;
	struct taurus_soc_data soc;
	struct resource *res;
	struct clk *clk;
	unsigned int i;
	int irq, ret;

	pcie = devm_kzalloc(dev, sizeof(*pcie), GFP_KERNEL);
	if (!pcie)
		return -ENOMEM;

	pci = &pcie->pci;
	pci->dev = dev;
	pci->ops = &taurus_pcie_ops;
	pci->pp.ops = &taurus_pcie_host_ops;
	raw_spin_lock_init(&pcie->intr_lock);
	platform_set_drvdata(pdev, pcie);

	ret = taurus_soc_data_get(&soc);
	if (ret)
		return dev_err_probe(dev, -EPROBE_DEFER,
				     "SoC revision not available\n");
	pcie->rev_a = soc.chip_revision == 'A';

	ret = of_property_read_u32(np, "id", &pcie->idx);
	if (ret)
		return dev_err_probe(dev, ret, "missing id property\n");

	pcie->lanes = 1;
	of_property_read_u32(np, "num-lanes", &pcie->lanes);
	if (!pcie->lanes || pcie->lanes > MAX_LANES)
		return dev_err_probe(dev, -EINVAL, "invalid num-lanes %u\n",
				     pcie->lanes);

	clk = devm_clk_get_enabled(dev, NULL);
	if (IS_ERR(clk))
		return dev_err_probe(dev, PTR_ERR(clk),
				     "failed to enable bus clock\n");

	pcie->glb = devm_platform_ioremap_resource_byname(pdev, "glbl_regs");
	if (IS_ERR(pcie->glb))
		return PTR_ERR(pcie->glb);

	res = platform_get_resource_byname(pdev, IORESOURCE_MEM, "serdes_phy");
	pcie->serdes = devm_ioremap_resource(dev, res);
	if (IS_ERR(pcie->serdes))
		return PTR_ERR(pcie->serdes);
	pcie->serdes_size = resource_size(res);

	ret = taurus_pcie_parse_serdes_cfg(pcie);
	if (ret)
		return ret;

	pcie->core_rst = devm_reset_control_get_exclusive(dev, "core_reset");
	if (IS_ERR(pcie->core_rst))
		return dev_err_probe(dev, PTR_ERR(pcie->core_rst),
				     "failed to get core_reset\n");

	pcie->phy_rst = devm_reset_control_get_exclusive(dev, "phy_reset");
	if (IS_ERR(pcie->phy_rst))
		return dev_err_probe(dev, PTR_ERR(pcie->phy_rst),
				     "failed to get phy_reset\n");

	pcie->perst = devm_gpiod_get_optional(dev, "reset", GPIOD_OUT_HIGH);
	if (IS_ERR(pcie->perst))
		return dev_err_probe(dev, PTR_ERR(pcie->perst),
				     "failed to get reset GPIO\n");

	for (i = 0; i < pcie->lanes; i++) {
		char name[16];

		snprintf(name, sizeof(name), "pcie-phy%u", i);
		pcie->phy[i] = devm_phy_get(dev, name);
		if (IS_ERR(pcie->phy[i]))
			return dev_err_probe(dev, PTR_ERR(pcie->phy[i]),
					     "failed to get %s\n", name);
	}

	ret = taurus_pcie_init_intx(pcie);
	if (ret)
		return ret;

	irq = platform_get_irq(pdev, 0);
	if (irq < 0)
		return irq;

	glb_write(pcie, 0, GLB_INTR_ENABLE);
	ret = devm_request_irq(dev, irq, taurus_pcie_irq_handler, 0,
			       dev_name(dev), pcie);
	if (ret)
		return dev_err_probe(dev, ret, "failed to request IRQ\n");

	pci->pp.msi_irq[0] = -ENODEV;

	return dw_pcie_host_init(&pci->pp);
}

static const struct of_device_id taurus_pcie_of_match[] = {
	{ .compatible = "realtek,taurus-pcie" },
	{ }
};

static struct platform_driver taurus_pcie_driver = {
	.probe	= taurus_pcie_probe,
	.driver	= {
		.name			= "taurus-pcie",
		.of_match_table		= taurus_pcie_of_match,
		.suppress_bind_attrs	= true,
	},
};
builtin_platform_driver(taurus_pcie_driver);
