// SPDX-License-Identifier: GPL-2.0-only
#ifndef _RTL9617C_PE_PROBE_H
#define _RTL9617C_PE_PROBE_H

#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/firmware.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/platform_device.h>
#include <linux/sizes.h>
#include <linux/unaligned.h>

#define PE_PROBE_BYTES		SZ_128K
#define PE_PROBE_BYTES_TX	SZ_512K
#define PE_PROBE_MAILBOX	0x2000
#define PE_PROBE_FIRMWARE	"rtl9617c/pe-radio.bin"
#define PE_PROBE_MAGIC		0x50455744

struct pe_probe {
	struct platform_device *device;
	void __iomem *reset, *atu, *ram, *bist;
	void *memory;
	dma_addr_t dma;
	u32 reset_saved, ram_saved, staging[8], entries[6][7], reset_mask;
	bool configured, staging_saved, attached;
	unsigned int slot, core;
};

int pe_probe_alloc(struct pe_probe *pe, unsigned int slot, unsigned int core);
int pe_probe_start(struct pe_probe *pe);
int pe_probe_stop(struct pe_probe *pe);
void pe_probe_free(struct pe_probe *pe);
void *pe_probe_engine_memory(struct pe_probe *pe);
#endif
