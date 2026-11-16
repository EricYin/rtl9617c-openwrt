// SPDX-License-Identifier: GPL-2.0-or-later
/* Semtech MCU calibration client; the vendor sequence lives below as static
 * helpers instead of a header full of code. */
#include <linux/delay.h>
#include <linux/i2c.h>
#include <linux/iopoll.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/nvmem-consumer.h>
#include <linux/of.h>
#include <linux/unaligned.h>
#include "pon/pon.h"
#include "rtl9617c_bosa.h"

enum rtl_bosa_model {
	RTL_BOSA_A2H = 100,
	RTL_BOSA_GN25L95 = 201,
	RTL_BOSA_GN25L98,
	RTL_BOSA_GN28L95,
	RTL_BOSA_GN28L96,
	RTL_BOSA_GN28L97,
};

struct rtl_bosa_io {
	void *context;
	int (*write)(void *context, unsigned int reg, unsigned char value);
	int (*read)(void *context, unsigned int reg, unsigned char *value);
	int (*wait)(void *context, unsigned int reg, unsigned char mask, unsigned char value);
};

static int rtl_bosa_range(const struct rtl_bosa_io *io, const unsigned char *cal,
				unsigned int offset, unsigned int first, unsigned int last)
{
	unsigned int reg;
	int ret;

	for (reg = first; reg <= last; reg++) {
		ret = io->write(io->context, reg, cal[offset + reg - first]);
		if (ret)
			return ret;
	}
	return 0;
}

static int rtl_bosa_modify(const struct rtl_bosa_io *io, unsigned int reg,
				 unsigned char mask, unsigned char value)
{
	unsigned char register_value;
	int ret = io->read(io->context, reg, &register_value);

	return ret ? ret : io->write(io->context, reg, (register_value & ~mask) | value);
}

static int rtl_bosa_calibrate(const struct rtl_bosa_io *io,
				    const unsigned char *cal, enum rtl_bosa_model model)
{
	unsigned int i;
	unsigned char value;
	int ret;

#define BOSA_WRITE(reg, val) do { ret = io->write(io->context, reg, val); if (ret) return ret; } while (0)
#define BOSA_RANGE(offset, first, last) do { ret = rtl_bosa_range(io, cal, offset, first, last); if (ret) return ret; } while (0)
#define BOSA_READ(reg) do { ret = io->read(io->context, reg, &value); if (ret) return ret; } while (0)
#define BOSA_MODIFY(reg, mask, val) do { ret = rtl_bosa_modify(io, reg, mask, val); if (ret) return ret; } while (0)

	if (model == RTL_BOSA_GN28L96 || model == RTL_BOSA_GN28L97) {
		BOSA_WRITE(0x7f, 0x81);
		BOSA_WRITE(0x89, 0);
		ret = io->wait(io->context, 0x89, 2, 2);
		if (ret)
			return ret;
		BOSA_RANGE(0x100, 0, 0x3f);
		BOSA_WRITE(0x6f, cal[0x16f]);
		BOSA_RANGE(0x170, 0x70, 0x77);
		BOSA_WRITE(0x7f, 0);
		BOSA_RANGE(0x1f8, 0xf8, 0xfd);
		BOSA_WRITE(0x7f, 0x82);
		BOSA_RANGE(0x300, 0x80, 0xff);
		BOSA_WRITE(0x7f, 0x83);
		BOSA_RANGE(0x380, 0x80, 0xff);
		BOSA_WRITE(0x7f, 0x80);
		BOSA_RANGE(0x200, 0x80, 0xff);
		BOSA_WRITE(0x7f, 0x81);
		for (i = 0x80; i <= 0xff; i++) {
			if (i == 0x88 || i == 0x8d || i == 0x8a)
				continue;
			BOSA_WRITE(i, cal[0x280 + i - 0x80]);
		}
		BOSA_WRITE(0x6e, cal[0x16e]);
		BOSA_READ(0x6e);
		BOSA_WRITE(0x88, cal[0x288]);
	} else if (model >= RTL_BOSA_GN25L95 && model <= RTL_BOSA_GN28L95) {
		BOSA_WRITE(0x7f, 4);
		BOSA_RANGE(0x280, 0x80, 0xff);
		BOSA_WRITE(0x7f, 5);
		BOSA_RANGE(0x300, 0x80, 0xff);
		BOSA_WRITE(0x7f, 6);
		BOSA_RANGE(0x380, 0x80, 0xff);
		BOSA_WRITE(0x7f, 2);
		BOSA_RANGE(0x200, 0x80, 0xff);
		BOSA_WRITE(0x7f, 2);
		BOSA_RANGE(0x252, 0xd2, 0xe7);
		BOSA_RANGE(0x100, 0, 0x4f);
		BOSA_WRITE(0x6f, cal[0x16f]);
		BOSA_WRITE(0x72, cal[0x172]);
		BOSA_WRITE(0x78, cal[0x178]);
		BOSA_WRITE(0x79, cal[0x179]);
		BOSA_WRITE(0x7f, 1);
		BOSA_WRITE(0xf8, cal[0x1f8]);
		BOSA_MODIFY(0xf9, 0xc0, 0xc0);
		BOSA_WRITE(0xfc, cal[0x1fc]);
		BOSA_MODIFY(0xfd, 0xc0, 0xc0);
		BOSA_READ(0x6e);
		BOSA_WRITE(0x6e, value | 0x40);
		BOSA_WRITE(0x6e, value & ~0x40);
		BOSA_WRITE(0x7f, 2);
		BOSA_WRITE(model == RTL_BOSA_GN25L95 ? 0xa0 : model == RTL_BOSA_GN25L98 ? 0x98 : 0x88, 0x6a);
		for (i = 0x7b; i <= 0x7e; i++)
			BOSA_WRITE(i, 0xff);
		BOSA_WRITE(0x7f, 2);
		BOSA_MODIFY(0xbb, 1, 0);
		BOSA_READ(0xbb);
		BOSA_WRITE(0x7f, 2);
		BOSA_READ(0xb1);
		BOSA_READ(0xb7);
	} else {
		return -EINVAL;
	}
#undef BOSA_WRITE
#undef BOSA_RANGE
#undef BOSA_READ
#undef BOSA_MODIFY
	return 0;
}

struct rtl_bosa {
	struct i2c_client *client;
	struct mutex lock;
	enum rtl_bosa_model model;
	bool configured;
	bool eeprom;
	unsigned int writes;
	int error;
	u8 identity[3];
};

static int rtl_bosa_write(void *context, unsigned int reg, unsigned char value)
{
	struct rtl_bosa *bosa = context;
	int ret = i2c_smbus_write_byte_data(bosa->client, reg, value);

	if (!ret)
		bosa->writes++;
	return ret;
}

static int rtl_bosa_read(void *context, unsigned int reg, unsigned char *value)
{
	struct rtl_bosa *bosa = context;
	int ret = i2c_smbus_read_byte_data(bosa->client, reg);

	if (ret < 0)
		return ret;
	*value = ret;
	return 0;
}

static int rtl_bosa_wait(void *context, unsigned int reg, unsigned char mask, unsigned char value)
{
	struct rtl_bosa *bosa = context;
	int status, ret;

	ret = read_poll_timeout(i2c_smbus_read_byte_data, status,
		status < 0 || (status & mask) == value, 1000, 1000000, false, bosa->client, reg);
	return status < 0 ? status : ret;
}

static int rtl_bosa_identify(struct rtl_bosa *bosa)
{
	u8 id, digital;
	int ret;
	unsigned int i;
	static const u8 registers[] = {0x80, 0x85, 0x86};

	ret = rtl_bosa_write(bosa, 0x7f, 0xff);
	if (ret)
		return ret;
	for (i = 0; i < ARRAY_SIZE(registers); i++) {
		ret = rtl_bosa_read(bosa, registers[i], &bosa->identity[i]);
		if (ret)
			return ret;
	}
	if (!memcmp(bosa->identity, "G96", 3))
		bosa->model = RTL_BOSA_GN28L96;
	else if (!memcmp(bosa->identity, "G97", 3))
		bosa->model = RTL_BOSA_GN28L97;
	else if (!memcmp(bosa->identity, "\xa1\0\0", 3))
		bosa->model = RTL_BOSA_GN28L95;
	else {
		u8 t_hi = 0xff, t_lo = 0xff;

		ret = rtl_bosa_write(bosa, 0x7f, 2);
		if (ret)
			return ret;
		ret = rtl_bosa_read(bosa, 0xd1, &id);
		if (ret)
			return ret;
		if ((id & 0xf0) == 0xa0)
			bosa->model = RTL_BOSA_GN25L95;
		else if ((id & 0xf0) == 0xc0)
			bosa->model = RTL_BOSA_GN25L98;
		else {
			/* A2h-only bare BOSA: A0h is all 0xff and the vendor
			 * pages carry no GN28L/25L ID.  A plausible base-page
			 * temperature identifies the module; its calibration
			 * and DDMI live in A2h. */
			ret = rtl_bosa_write(bosa, 0x7f, 0);
			if (ret)
				return ret;
			ret = rtl_bosa_read(bosa, 0x60, &t_hi);
			if (!ret)
				ret = rtl_bosa_read(bosa, 0x61, &t_lo);
			if (ret)
				return ret;
			if ((t_hi == 0xff && t_lo == 0xff) ||
			    (t_hi == 0x00 && t_lo == 0x00))
				return -ENODEV;
			bosa->identity[0] = 'A';
			bosa->identity[1] = '2';
			bosa->identity[2] = 'H';
			bosa->model = RTL_BOSA_A2H;
			bosa->eeprom = true;
			return 0;
		}
	}
	ret = rtl_bosa_write(bosa, 0x7f, bosa->model >= RTL_BOSA_GN28L96 ? 0x81 : 2);
	if (ret)
		return ret;
	ret = rtl_bosa_read(bosa, bosa->model >= RTL_BOSA_GN28L96 ? 0x89 :
		bosa->model == RTL_BOSA_GN28L95 ? 0xc7 : 0xc0, &digital);
	if (ret)
		return ret;
	/* The shipping GN28L96/97 EEPROM-present flag has inverse polarity. */
	bosa->eeprom = bosa->model >= RTL_BOSA_GN28L96 ? !(digital & 1) : digital & 1;
	return 0;
}

#define RTL_BOSA_CALIBRATION_SIZE	1024

static bool rtl_bosa_calibration_present(const u8 *data, size_t length)
{
	size_t i;

	if (length < RTL_BOSA_CALIBRATION_SIZE)
		return false;
	for (i = 0; i < length; i++)
		if (data[i] != 0xff)
			return true;
	return false;
}

static int rtl_bosa_apply_calibration(struct rtl_bosa *bosa,
				      const struct rtl_bosa_io *io)
{
	struct nvmem_cell *cell;
	u8 *data;
	size_t length;
	int ret;

	cell = nvmem_cell_get(&bosa->client->dev, "calibration");
	if (IS_ERR(cell))
		return PTR_ERR(cell);
	data = nvmem_cell_read(cell, &length);
	nvmem_cell_put(cell);
	if (IS_ERR(data))
		return PTR_ERR(data);
	if (!rtl_bosa_calibration_present(data, length)) {
		kfree(data);
		return -ENODATA;
	}
	ret = rtl_bosa_calibrate(io, data, bosa->model);
	kfree(data);
	return ret;
}

static int rtl_bosa_configure(struct rtl_bosa *bosa)
{
	struct rtl_bosa_io io = {
		.context = bosa,
		.write = rtl_bosa_write,
		.read = rtl_bosa_read,
		.wait = rtl_bosa_wait,
	};
	u8 page, tx;
	int ret, restore;

	mutex_lock(&bosa->lock);
	bosa->configured = false;
	bosa->writes = 0;
	ret = rtl_bosa_read(bosa, 0x7f, &page);
	if (ret)
		goto unlock;
	ret = rtl_bosa_identify(bosa);
	if (ret)
		goto restore;
	ret = rtl_bosa_apply_calibration(bosa, &io);
	if (ret) {
		if (bosa->eeprom) {
			ret = 0;
		} else {
			dev_warn(&bosa->client->dev, "BOSA has no EEPROM and no calibration: %d\n",
				 ret);
			goto restore;
		}
	}
	ret = rtl_bosa_read(bosa, 0x6e, &tx);
	if (!ret && tx & BIT(6))
		ret = -EIO;
	if (!ret) {
		bosa->configured = true;
		dev_info(&bosa->client->dev, "BOSA model=%u EEPROM=%u, %u writes, tx_control=%02x\n",
			 bosa->model, bosa->eeprom, bosa->writes, tx);
	}
restore:
	restore = rtl_bosa_write(bosa, 0x7f, page);
	if (!ret)
		ret = restore;
unlock:
	if (ret)
		bosa->configured = false;
	bosa->error = ret;
	mutex_unlock(&bosa->lock);
	return ret;
}

int rtl9617c_bosa_prepare(struct device *device)
{
	return rtl_bosa_configure(dev_get_drvdata(device));
}
EXPORT_SYMBOL_GPL(rtl9617c_bosa_prepare);

ssize_t rtl9617c_bosa_state(struct device *dev, char *buf)
{
	struct rtl_bosa *bosa = dev_get_drvdata(dev);

	return sysfs_emit(buf, "configured=%u model=%u eeprom=%u writes=%u error=%d identity=%02x/%02x/%02x\n",
		bosa->configured, bosa->model, bosa->eeprom, bosa->writes, bosa->error,
		bosa->identity[0], bosa->identity[1], bosa->identity[2]);
}

EXPORT_SYMBOL_GPL(rtl9617c_bosa_state);

static ssize_t configure_show(struct device *dev, struct device_attribute *attribute, char *buf)
{
	return rtl9617c_bosa_state(dev, buf);
}

DEVICE_ATTR_RO(configure);

ssize_t rtl9617c_bosa_diagnostics(struct device *dev, char *buf)
{
	struct rtl_bosa *bosa = dev_get_drvdata(dev);
	u8 data[14];
	int ret;
	unsigned int i;

	mutex_lock(&bosa->lock);
	for (i = 0; i < ARRAY_SIZE(data); i++) {
		ret = rtl_bosa_read(bosa, 0x60 + i, &data[i]);
		if (ret)
			goto unlock;
	}
	ret = sysfs_emit(buf, "temperature_raw=%d voltage_raw=%u bias_raw=%u tx_power_raw=%u rx_power_raw=%u control=%02x/%02x/%02x/%02x\n",
		(s16)get_unaligned_be16(data), get_unaligned_be16(data + 2),
		get_unaligned_be16(data + 4), get_unaligned_be16(data + 6),
		get_unaligned_be16(data + 8), data[10], data[11], data[12], data[13]);
unlock:
	mutex_unlock(&bosa->lock);
	return ret;
}
EXPORT_SYMBOL_GPL(rtl9617c_bosa_diagnostics);

static ssize_t diagnostics_show(struct device *dev, struct device_attribute *attribute, char *buf)
{
	return rtl9617c_bosa_diagnostics(dev, buf);
}
DEVICE_ATTR_RO(diagnostics);

static struct attribute *rtl_bosa_attrs[] = {
	&dev_attr_configure.attr,
	&dev_attr_diagnostics.attr,
	NULL,
};
ATTRIBUTE_GROUPS(rtl_bosa);

static int rtl_bosa_probe(struct i2c_client *client)
{
	struct rtl_bosa *bosa = devm_kzalloc(&client->dev, sizeof(*bosa), GFP_KERNEL);

	if (!bosa)
		return -ENOMEM;
	bosa->client = client;
	mutex_init(&bosa->lock);
	i2c_set_clientdata(client, bosa);
	return 0;
}

static const struct of_device_id rtl_bosa_match[] = {
	{ .compatible = "realtek,rtl9617c-bosa" },
	{ }
};
MODULE_DEVICE_TABLE(of, rtl_bosa_match);

static struct i2c_driver rtl_bosa_driver = {
	.probe = rtl_bosa_probe,
	.driver = {
		.name = "rtl9617c-bosa",
		.of_match_table = rtl_bosa_match,
		.dev_groups = rtl_bosa_groups,
	},
};
module_i2c_driver(rtl_bosa_driver);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("RTL9617C native Semtech BOSA calibration client");
