// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/bitfield.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/mod_devicetable.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/spi/spi.h>
#include <linux/spi/spi-mem.h>

#define RTL9617C_QSPI_TYPE		0x0c
#define RTL9617C_QSPI_ACCESS_START	0x10
#define RTL9617C_QSPI_SF_ACCESS		0x30
#define RTL9617C_QSPI_SF_EXT_ACCESS	0x34
#define RTL9617C_QSPI_SF_ADDRESS	0x38
#define RTL9617C_QSPI_SF_DATA		0x3c

#define RTL9617C_QSPI_TYPE_SIZE_MASK	GENMASK(10, 9)
#define RTL9617C_QSPI_TYPE_SIZE_4B	(2 << 9)

#define RTL9617C_QSPI_START		BIT(1)
#define RTL9617C_QSPI_WRITE		BIT(9)
#define RTL9617C_QSPI_BUSY		BIT(16)
#define RTL9617C_QSPI_BUSY_MASK		(RTL9617C_QSPI_BUSY | RTL9617C_QSPI_START)

#define RTL9617C_QSPI_ACC_CMD		0x0
#define RTL9617C_QSPI_ACC_ADDR		(5 << 8)
#define RTL9617C_QSPI_ACC_EXTEND		(15 << 8)
#define RTL9617C_QSPI_ACC_TERM		BIT(12)
#define RTL9617C_QSPI_ACC_BURST		BIT(13)

#define RTL9617C_QSPI_ACC_MIO		GENMASK(31, 30)
#define RTL9617C_QSPI_ACC_MIO_DATA	BIT(24)
#define RTL9617C_QSPI_ACC_MIO_DUAL	1
#define RTL9617C_QSPI_ACC_MIO_QUAD	2

#define RTL9617C_QSPI_EXT_OPCODE		GENMASK(7, 0)
#define RTL9617C_QSPI_EXT_DATA_CNT	GENMASK(20, 8)
#define RTL9617C_QSPI_EXT_ADDR_CNT	GENMASK(23, 21)
#define RTL9617C_QSPI_EXT_DUMMY_CNT	GENMASK(29, 24)
#define RTL9617C_QSPI_EXT_RD_CMD_EN	BIT(31)

#define RTL9617C_QSPI_MAX_DATA		2048
#define RTL9617C_QSPI_TIMEOUT_US	100000

struct rtl9617c_qspi {
	void __iomem *base;
};

static int rtl9617c_qspi_wait(struct rtl9617c_qspi *qspi)
{
	u32 val;

	return readl_poll_timeout_atomic(qspi->base + RTL9617C_QSPI_ACCESS_START,
					 val, !(val & RTL9617C_QSPI_BUSY_MASK),
					 0, RTL9617C_QSPI_TIMEOUT_US);
}

static int rtl9617c_qspi_kick(struct rtl9617c_qspi *qspi, bool write)
{
	writel(RTL9617C_QSPI_START | (write ? RTL9617C_QSPI_WRITE : 0),
	       qspi->base + RTL9617C_QSPI_ACCESS_START);
	return rtl9617c_qspi_wait(qspi);
}

static unsigned int rtl9617c_qspi_dummy_cycles(const struct spi_mem_op *op)
{
	if (!op->dummy.nbytes)
		return 0;

	return op->dummy.nbytes * 8 / op->dummy.buswidth;
}

static u32 rtl9617c_qspi_access(const struct spi_mem_op *op)
{
	u32 access = RTL9617C_QSPI_ACC_EXTEND;

	if (op->data.nbytes > 4)
		access |= RTL9617C_QSPI_ACC_BURST;

	switch (op->data.buswidth) {
	case 4:
		access |= RTL9617C_QSPI_ACC_MIO_DATA |
			  FIELD_PREP(RTL9617C_QSPI_ACC_MIO,
				     RTL9617C_QSPI_ACC_MIO_QUAD);
		break;
	case 2:
		access |= RTL9617C_QSPI_ACC_MIO_DATA |
			  FIELD_PREP(RTL9617C_QSPI_ACC_MIO,
				     RTL9617C_QSPI_ACC_MIO_DUAL);
		break;
	}

	return access;
}

static u32 rtl9617c_qspi_ext_access(const struct spi_mem_op *op)
{
	unsigned int dummy = rtl9617c_qspi_dummy_cycles(op);
	u32 addr_cnt = op->addr.nbytes ? op->addr.nbytes - 1 : 0x7;
	u32 dummy_cnt = dummy ? dummy - 1 : 0x3f;

	return FIELD_PREP(RTL9617C_QSPI_EXT_OPCODE, op->cmd.opcode) |
	       FIELD_PREP(RTL9617C_QSPI_EXT_DATA_CNT, op->data.nbytes - 1) |
	       FIELD_PREP(RTL9617C_QSPI_EXT_ADDR_CNT, addr_cnt) |
	       FIELD_PREP(RTL9617C_QSPI_EXT_DUMMY_CNT, dummy_cnt) |
	       RTL9617C_QSPI_EXT_RD_CMD_EN;
}

static int rtl9617c_qspi_data(struct rtl9617c_qspi *qspi,
			      const struct spi_mem_op *op)
{
	bool out = op->data.dir == SPI_MEM_DATA_OUT;
	bool burst = op->data.nbytes > 4;
	unsigned int offset = 0;
	int ret = 0;

	writel(rtl9617c_qspi_access(op), qspi->base + RTL9617C_QSPI_SF_ACCESS);
	writel(0, qspi->base + RTL9617C_QSPI_SF_EXT_ACCESS);
	writel(rtl9617c_qspi_ext_access(op),
	       qspi->base + RTL9617C_QSPI_SF_EXT_ACCESS);
	if (op->addr.nbytes)
		writel(op->addr.val, qspi->base + RTL9617C_QSPI_SF_ADDRESS);

	while (offset < op->data.nbytes) {
		unsigned int n = min_t(unsigned int, op->data.nbytes - offset, 4);
		unsigned int i;

		if (out) {
			const u8 *buf = op->data.buf.out;
			u32 word = 0;

			for (i = 0; i < n; i++)
				word |= (u32)buf[offset + i] << (8 * i);
			writel(word, qspi->base + RTL9617C_QSPI_SF_DATA);
		}

		ret = rtl9617c_qspi_kick(qspi, out);
		if (ret)
			break;

		if (!out) {
			u8 *buf = op->data.buf.in;
			u32 word = readl(qspi->base + RTL9617C_QSPI_SF_DATA);

			for (i = 0; i < n; i++)
				buf[offset + i] = word >> (8 * i);
		}

		offset += n;
	}

	if (burst) {
		u32 access = readl(qspi->base + RTL9617C_QSPI_SF_ACCESS);

		access &= ~RTL9617C_QSPI_ACC_BURST;
		access |= RTL9617C_QSPI_ACC_TERM;
		writel(access, qspi->base + RTL9617C_QSPI_SF_ACCESS);
	}
	writel(0, qspi->base + RTL9617C_QSPI_SF_ACCESS);

	return ret;
}

static int rtl9617c_qspi_exec_op(struct spi_mem *mem,
				 const struct spi_mem_op *op)
{
	struct rtl9617c_qspi *qspi =
		spi_controller_get_devdata(mem->spi->controller);
	u32 type;
	int ret;

	if (op->data.nbytes)
		return rtl9617c_qspi_data(qspi, op);

	type = readl(qspi->base + RTL9617C_QSPI_TYPE) &
	       ~RTL9617C_QSPI_TYPE_SIZE_MASK;
	if (op->addr.nbytes == 4)
		type |= RTL9617C_QSPI_TYPE_SIZE_4B;
	writel(type, qspi->base + RTL9617C_QSPI_TYPE);
	writel(op->cmd.opcode |
	       (op->addr.nbytes ? RTL9617C_QSPI_ACC_ADDR :
				  RTL9617C_QSPI_ACC_CMD),
	       qspi->base + RTL9617C_QSPI_SF_ACCESS);
	if (op->addr.nbytes)
		writel(op->addr.val, qspi->base + RTL9617C_QSPI_SF_ADDRESS);

	ret = rtl9617c_qspi_kick(qspi, false);
	if (!ret)
		usleep_range(10, 20);
	writel(0, qspi->base + RTL9617C_QSPI_SF_ACCESS);

	return ret;
}

static bool rtl9617c_qspi_supports_op(struct spi_mem *mem,
				      const struct spi_mem_op *op)
{
	if (op->cmd.nbytes != 1 || op->cmd.buswidth != 1)
		return false;
	if (op->addr.nbytes > 4 ||
	    (op->addr.nbytes && op->addr.buswidth != 1))
		return false;
	if (op->dummy.nbytes > 8 ||
	    (op->dummy.nbytes && op->dummy.buswidth != 1))
		return false;
	if (op->cmd.dtr || op->addr.dtr || op->dummy.dtr || op->data.dtr)
		return false;
	if (op->data.dir != SPI_MEM_NO_DATA &&
	    op->data.buswidth != 1 && op->data.buswidth != 2 &&
	    op->data.buswidth != 4)
		return false;
	if (op->data.dir == SPI_MEM_NO_DATA) {
		if (op->dummy.nbytes)
			return false;
		if (op->addr.nbytes && op->addr.nbytes != 3 &&
		    op->addr.nbytes != 4)
			return false;
	}

	return spi_mem_default_supports_op(mem, op);
}

static int rtl9617c_qspi_adjust_op_size(struct spi_mem *mem,
					struct spi_mem_op *op)
{
	op->data.nbytes = min_t(unsigned int, op->data.nbytes,
				RTL9617C_QSPI_MAX_DATA);
	return 0;
}

static const struct spi_controller_mem_ops rtl9617c_qspi_mem_ops = {
	.supports_op = rtl9617c_qspi_supports_op,
	.adjust_op_size = rtl9617c_qspi_adjust_op_size,
	.exec_op = rtl9617c_qspi_exec_op,
};

static int rtl9617c_qspi_probe(struct platform_device *pdev)
{
	struct spi_controller *ctlr;
	struct rtl9617c_qspi *qspi;

	ctlr = devm_spi_alloc_host(&pdev->dev, sizeof(*qspi));
	if (!ctlr)
		return -ENOMEM;

	qspi = spi_controller_get_devdata(ctlr);
	qspi->base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(qspi->base))
		return PTR_ERR(qspi->base);

	ctlr->num_chipselect = 1;
	ctlr->mode_bits = SPI_RX_DUAL | SPI_RX_QUAD |
			  SPI_TX_DUAL | SPI_TX_QUAD;
	ctlr->bits_per_word_mask = SPI_BPW_MASK(8);
	ctlr->mem_ops = &rtl9617c_qspi_mem_ops;
	ctlr->dev.of_node = pdev->dev.of_node;

	return devm_spi_register_controller(&pdev->dev, ctlr);
}

static const struct of_device_id rtl9617c_qspi_of_match[] = {
	{ .compatible = "realtek,rtl9617c-qspi" },
	{ }
};
MODULE_DEVICE_TABLE(of, rtl9617c_qspi_of_match);

static struct platform_driver rtl9617c_qspi_driver = {
	.probe = rtl9617c_qspi_probe,
	.driver = {
		.name = "rtl9617c-qspi",
		.of_match_table = rtl9617c_qspi_of_match,
	},
};
module_platform_driver(rtl9617c_qspi_driver);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Realtek RTL9617C QSPI controller");
