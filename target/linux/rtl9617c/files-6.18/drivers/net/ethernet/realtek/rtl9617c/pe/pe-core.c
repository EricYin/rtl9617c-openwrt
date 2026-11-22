// SPDX-License-Identifier: GPL-2.0-only
#include "pe_probe.h"

static struct pe_probe *pe_engines[2];
static unsigned int pe_engine_users[2];
static DEFINE_MUTEX(pe_engine_lock);

static int pe_probe_access(struct pe_probe *pe, u32 command)
{
	u32 state;
	writel(command, pe->atu);
	return readl_poll_timeout(pe->atu, state, !(state & (BIT(30) | BIT(31))), 1, 10000);
}

static void pe_probe_reset(struct pe_probe *pe, u32 bits)
{
	writel((readl(pe->reset) & ~pe->reset_mask) | bits, pe->reset);
	readl(pe->reset);
}

static void pe_probe_core_stop(struct pe_probe *pe)
{
	if (!pe->configured) return;
	pe_probe_reset(pe, pe->reset_mask);
	writel(readl(pe->ram) | BIT(5), pe->ram);
	udelay(1000);
}

static void pe_probe_core_free(struct pe_probe *pe)
{
	unsigned int index, i;

	pe_probe_core_stop(pe);
	if (pe->configured) {
		for (index = 0; index < 6; index++) {
			for (i = 0; i < 7; i++)
				writel(pe->entries[index][i], pe->atu + 4 + i * 4);
			pe_probe_access(pe, (pe->staging[0] & 255) | index << 24 | BIT(31));
		}
		writel(pe->ram_saved, pe->ram);
		pe_probe_reset(pe, pe->reset_saved & pe->reset_mask);
	}
	if (pe->staging_saved) {
		for (i = 1; i < 8; i++)
			writel(pe->staging[i], pe->atu + i * 4);
		writel(pe->staging[0] & ~(BIT(30) | BIT(31)), pe->atu);
	}
	if (pe->memory)
		dma_free_coherent(&pe->device->dev, PE_PROBE_BYTES, pe->memory, pe->dma);
	if (pe->device)
		platform_device_unregister(pe->device);
}

static int pe_probe_core_alloc(struct pe_probe *pe)
{
	unsigned int i, index;
	int ret;

	pe->reset_saved = readl(pe->reset);
	pe->ram_saved = readl(pe->ram);
	for (i = 0; i < 8; i++) pe->staging[i] = readl(pe->atu + i * 4);
	pe->staging_saved = true;
	if (!(pe->reset_saved & BIT(20 + pe->core)) || (pe->staging[0] & 14)) return -EBUSY;
	for (index = 0; index < 6; index++) {
		ret = pe_probe_access(pe, (pe->staging[0] & 255) | index << 24 | BIT(30));
		if (ret) return ret;
		for (i = 0; i < 7; i++) pe->entries[index][i] = readl(pe->atu + 4 + i * 4);
	}
	pe->device = platform_device_register_simple("tyfza1-pe-probe", pe->core, NULL, 0);
	if (IS_ERR(pe->device)) { ret = PTR_ERR(pe->device); pe->device = NULL; return ret; }
	ret = dma_coerce_mask_and_coherent(&pe->device->dev, DMA_BIT_MASK(32));
	if (ret) return ret;
	pe->memory = dma_alloc_coherent(&pe->device->dev, PE_PROBE_BYTES, &pe->dma, GFP_KERNEL);
	if (!pe->memory) return -ENOMEM;
	if (!IS_ALIGNED(pe->dma, PE_PROBE_BYTES)) return -EINVAL;
	memset(pe->memory, 0, PE_PROBE_BYTES);
	return 0;
}

static int pe_probe_core_start(struct pe_probe *pe)
{
	static const u32 input[] = { 0x1fc0, 0x1000, 0x1100, 0x1200, 0x1300, 0x0fc0 };
	static const u32 output[] = { 0, 0xf430, 0xa040, 0xb040, 0xf700, 0 };
	u32 bist_control;
	unsigned int index, i;
	int ret;

	pe->configured = true;
	pe_probe_core_stop(pe);
	bist_control = readl(pe->bist);
	writel(bist_control & ~BIT(18), pe->bist);
	readl(pe->bist);
	for (index = 0; index < 6; index++) {
		writel(input[index], pe->atu + 4);
		writel(index && index != 5 ? 0xfff0 : 0xffff, pe->atu + 8);
		writel(index && index != 5 ? output[index] : pe->dma >> 16, pe->atu + 12);
		for (i = 3; i < 7; i++) writel(pe->entries[0][i], pe->atu + 4 + i * 4);
		ret = pe_probe_access(pe, (pe->staging[0] & 255) | 63 | index << 24 | BIT(31));
		if (ret) return ret;
	}
	writel(readl(pe->ram) & ~BIT(5), pe->ram);
	pe_probe_reset(pe, BIT(20 + pe->core));
	udelay(1000);
	pe_probe_reset(pe, 0);
	return 0;
}

static int pe_probe_engine_firmware_load(struct pe_probe *pe)
{
	const struct firmware *fw;
	const u32 *program;
	u32 address, status;
	int ret;

	ret = request_firmware(&fw, PE_PROBE_FIRMWARE, &pe->device->dev);
	if (ret) return ret;
	if (fw->size % 4 || fw->size > PE_PROBE_BYTES) { ret = -EINVAL; goto out; }
	program = (const u32 *)fw->data;
	memcpy(pe->memory, program, fw->size);
	address = (u32)(pe->dma + PE_PROBE_MAILBOX) | 0xa0000000U;
	put_unaligned_le32(program[0] | address >> 16, pe->memory);
	put_unaligned_le32(program[1] | (address & 0xffff), pe->memory + 4);
	put_unaligned_le32(program[2] | ((u32)pe->dma | 0x80000000U) >> 16, pe->memory + 8);
	put_unaligned_le32(program[0x380 / 4] | address >> 16, pe->memory + 0x380);
	put_unaligned_le32(program[0x384 / 4] | (address & 0xffff), pe->memory + 0x384);
	dma_wmb();
	ret = pe_probe_core_start(pe);
	if (ret) goto out;
	ret = read_poll_timeout(get_unaligned_le32, status, status == PE_PROBE_MAGIC,
		10, 100000, false, pe->memory + PE_PROBE_MAILBOX);
out:
	release_firmware(fw);
	return ret;
}

int pe_probe_alloc(struct pe_probe *pe, unsigned int slot, unsigned int core)
{
	struct pe_probe *pe_engine;
	unsigned int bytes;
	int ret;

	pe->core = core;
	mutex_lock(&pe_engine_lock);
	pe_engine = pe_engines[core];
	if (!pe_engine) {
		pe_engine = kzalloc(sizeof(*pe_engine), GFP_KERNEL);
		if (!pe_engine) { ret = -ENOMEM; goto unlock; }
		pe_engine->core = core;
		ret = pe_probe_core_alloc(pe_engine);
		if (ret) { pe_probe_core_free(pe_engine); kfree(pe_engine); pe_engine = NULL; goto unlock; }
	}
	pe->device = pe_engine->device;
	pe->reset = pe_engine->reset;
	pe->atu = pe_engine->atu;
	pe->ram = pe_engine->ram;
	pe->bist = pe_engine->bist;
	pe->slot = slot;
	bytes = core == 1 ? PE_PROBE_BYTES_TX : PE_PROBE_BYTES;
	pe->memory = dma_alloc_coherent(&pe->device->dev, bytes, &pe->dma, GFP_KERNEL);
	if (!pe->memory) {
		if (!pe_engine_users[core]) { pe_probe_core_free(pe_engine); kfree(pe_engine); pe_engine = NULL; }
		pe->device = NULL;
		ret = -ENOMEM;
		goto unlock;
	}
	memset(pe->memory, 0, bytes);
	pe_engine_users[core]++;
	ret = 0;
unlock:
	pe_engines[core] = pe_engine;
	mutex_unlock(&pe_engine_lock);
	return ret;
}

int pe_probe_start(struct pe_probe *pe)
{
	struct pe_probe *pe_engine = pe_engines[pe->core];
	u8 *control;
	u32 generation, status;
	int ret;

	mutex_lock(&pe_engine_lock);
	if (!pe_engine->configured) {
		ret = pe_probe_engine_firmware_load(pe_engine);
		if (ret) goto unlock;
	}
	control = pe_engine->memory + PE_PROBE_MAILBOX;
	generation = get_unaligned_le32(control + (142 + pe->slot) * 4) + 1;
	put_unaligned_le32((u32)(pe->dma + PE_PROBE_MAILBOX) | 0xa0000000U,
		control + (140 + pe->slot) * 4);
	dma_wmb();
	put_unaligned_le32(generation, control + (142 + pe->slot) * 4);
	pe->attached = true;
	ret = read_poll_timeout(get_unaligned_le32, status, status == PE_PROBE_MAGIC,
		10, 100000, false, pe->memory + PE_PROBE_MAILBOX);
unlock:
	mutex_unlock(&pe_engine_lock);
	return ret;
}

int pe_probe_stop(struct pe_probe *pe)
{
	struct pe_probe *pe_engine = pe_engines[pe->core];
	u32 generation, status;
	int ret;

	if (!pe->attached) return 0;
	mutex_lock(&pe_engine_lock);
	control = pe_engine->memory + PE_PROBE_MAILBOX;
	generation = get_unaligned_le32(control + (142 + pe->slot) * 4) + 1;
	put_unaligned_le32(0, control + (140 + pe->slot) * 4);
	dma_wmb();
	put_unaligned_le32(generation, control + (142 + pe->slot) * 4);
	ret = read_poll_timeout(get_unaligned_le32, status, status == generation,
		10, 100000, false, control + (144 + pe->slot) * 4);
	if (!ret) pe->attached = false;
	mutex_unlock(&pe_engine_lock);
	return ret;
}

void pe_probe_free(struct pe_probe *pe)
{
	struct pe_probe *pe_engine = pe_engines[pe->core];
	unsigned int bytes;

	if (!pe->memory) return;
	if (pe_probe_stop(pe)) return;
	mutex_lock(&pe_engine_lock);
	bytes = pe->core == 1 ? PE_PROBE_BYTES_TX : PE_PROBE_BYTES;
	dma_free_coherent(&pe->device->dev, bytes, pe->memory, pe->dma);
	if (!--pe_engine_users[pe->core]) {
		pe_probe_core_free(pe_engine);
		kfree(pe_engine);
		pe_engines[pe->core] = NULL;
	}
	mutex_unlock(&pe_engine_lock);
}

void *pe_probe_engine_memory(struct pe_probe *pe) { return pe_engines[pe->core]->memory; }
EXPORT_SYMBOL_GPL(pe_probe_alloc);
EXPORT_SYMBOL_GPL(pe_probe_start);
EXPORT_SYMBOL_GPL(pe_probe_stop);
EXPORT_SYMBOL_GPL(pe_probe_free);
EXPORT_SYMBOL_GPL(pe_probe_engine_memory);

static int rtl9617c_pe_probe(struct platform_device *pdev)
{
	struct pe_probe *pe;
	u32 core;
	int ret;

	ret = device_property_read_u32(&pdev->dev, "realtek,pe-index", &core);
	if (ret) return ret;
	if (core >= 2) return -EINVAL;
	mutex_lock(&pe_engine_lock);
	if (pe_engines[core]) { ret = -EBUSY; goto unlock; }
	pe = kzalloc(sizeof(*pe), GFP_KERNEL);
	if (!pe) { ret = -ENOMEM; goto unlock; }
	pe->core = core;
	pe->reset_mask = BIT(18 + core) | BIT(20 + core);
	pe->reset = devm_platform_ioremap_resource_byname(pdev, "reset");
	pe->atu = devm_platform_ioremap_resource_byname(pdev, "atu");
	pe->ram = devm_platform_ioremap_resource_byname(pdev, "ram-ctrl");
	pe->bist = devm_platform_ioremap_resource_byname(pdev, "bist");
	if (IS_ERR(pe->reset) || IS_ERR(pe->atu) || IS_ERR(pe->ram) || IS_ERR(pe->bist)) {
		ret = -EINVAL;
		kfree(pe);
		goto unlock;
	}
	pe_engines[core] = pe;
	platform_set_drvdata(pdev, pe);
unlock:
	mutex_unlock(&pe_engine_lock);
	return ret;
}

static int rtl9617c_pe_remove(struct platform_device *pdev)
{
	struct pe_probe *pe = platform_get_drvdata(pdev);

	mutex_lock(&pe_engine_lock);
	if (pe_engine_users[pe->core]) { mutex_unlock(&pe_engine_lock); return -EBUSY; }
	pe_engines[pe->core] = NULL;
	mutex_unlock(&pe_engine_lock);
	kfree(pe);
	return 0;
}

static const struct of_device_id rtl9617c_pe_of_match[] = {
	{ .compatible = "realtek,rtl9617c-pe" },
	{ },
};
MODULE_DEVICE_TABLE(of, rtl9617c_pe_of_match);

static struct platform_driver rtl9617c_pe_driver = {
	.probe = rtl9617c_pe_probe,
	.remove = rtl9617c_pe_remove,
	.driver = {
		.name = "rtl9617c-pe",
		.of_match_table = rtl9617c_pe_of_match,
	},
};
module_platform_driver(rtl9617c_pe_driver);
MODULE_LICENSE("GPL");
