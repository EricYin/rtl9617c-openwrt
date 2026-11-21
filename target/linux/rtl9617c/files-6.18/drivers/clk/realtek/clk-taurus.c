// SPDX-License-Identifier: GPL-2.0
#include <linux/clk-provider.h>
#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/slab.h>

#define TAURUS_REG_GLOBAL_CONFIG	0x0c0
#define TAURUS_REG_STRAP		0x0ac
#define TAURUS_REG_CPLLDIV		0x200
#define TAURUS_REG_CPLLMUX		0x204
#define TAURUS_REG_EPLLDIV		0x208
#define TAURUS_REG_EPLLDIV2		0x20c
#define TAURUS_REG_PEDIV		0x210
#define TAURUS_REG_CPLL0		0x230
#define TAURUS_REG_EPLL0		0x238
#define TAURUS_REG_FPLL0		0x240

#define TAURUS_DIVN_BASE		3
#define TAURUS_DIVN_SHIFT		0
#define TAURUS_DIVN_WIDTH		8
#define TAURUS_PREDIV_BASE		2
#define TAURUS_PREDIV_SHIFT		12
#define TAURUS_PREDIV_WIDTH		2
#define TAURUS_CPLL_RSTB_SHIFT		10
#define TAURUS_CPLL_RSTB_WIDTH		2

#define TAURUS_CPLLDIV_CORTEX_SHIFT	0
#define TAURUS_CPLLDIV_CORTEX_WIDTH	6
#define TAURUS_CPLLDIV_OVERRIDE		6
#define TAURUS_CPLLDIV_F2C_SHIFT	7
#define TAURUS_CPLLDIV_F2C_WIDTH	4
#define TAURUS_CPLLDIV_CF_SEL		11
#define TAURUS_CPLLDIV_MODE_OVERRIDE	31

#define TAURUS_PEDIV_OFFLOAD_SEL	6
#define TAURUS_PEDIV_FULLSPEED_SEL	22

#define TAURUS_STRAP_SPEED_SHIFT	1
#define TAURUS_STRAP_SPEED_WIDTH	3

#define TAURUS_CPLLMUX_MAGIC		0xff000000

#define TAURUS_DELAY_PLL_FOR_LOCK	200
#define TAURUS_DELAY_PLL_FOR_SWITCH	10

#define clk_mask(width)			((1 << (width)) - 1)

#define to_taurus_pll_clk(_hw)		container_of(_hw, struct taurus_pll_clk, hw)
#define to_taurus_cpu_daemon(_hw)	container_of(_hw, struct taurus_cpu_daemon, hw)

enum {
	TAURUS_CLK_PLL,
	TAURUS_CLK_DIVIDER,
	TAURUS_CLK_MUX,
	TAURUS_CLK_GATE,
	TAURUS_CLK_FIXED_FACTOR,
	TAURUS_CLK_PE_DAEMON,
	TAURUS_CLK_CPU_DAEMON,
};

enum {
	TAURUS_CPUD_REF,
	TAURUS_CPUD_CPLL,
	TAURUS_CPUD_DIV_F2C,
	TAURUS_CPUD_MUX_CPU,
	TAURUS_CPUD_DIV_CORTEX,
	TAURUS_CPUD_CLKS_NUM,
};

struct taurus_clk_reg {
	void __iomem *regbase;
	spinlock_t regs_lock;
};

struct taurus_clk_param {
	int type;
	u32 reg;
};

struct taurus_pll_clk {
	void __iomem *reg;
	spinlock_t *lock;
	struct clk_hw hw;
};

struct taurus_pll_param {
	unsigned int pll;
	unsigned int prediv;
	unsigned int divn;
};

struct taurus_cpu_strap_speed {
	unsigned int pll;
	unsigned int div;
};

struct taurus_pe_speed {
	unsigned int pll;
	unsigned int div;
};

struct taurus_cpu_daemon {
	void __iomem *reg;
	struct mutex mlock;
	spinlock_t *lock;
	struct clk_hw hw;
	struct clk *clks[TAURUS_CPUD_CLKS_NUM];
};

static const struct taurus_pll_param taurus_pll_param_table[] = {
	{ .pll = 40, .prediv = 5, .divn = 200, },
	{ .pll = 44, .prediv = 5, .divn = 220, },
	{ .pll = 48, .prediv = 5, .divn = 240, },
	{ .pll = 50, .prediv = 5, .divn = 250, },
	{ .pll = 56, .prediv = 3, .divn = 168, },
	{ .pll = 64, .prediv = 3, .divn = 192, },
	{ .pll = 72, .prediv = 3, .divn = 216, },
	{ .pll = 80, .prediv = 2, .divn = 160, },
};

static const struct taurus_cpu_strap_speed taurus_cpu_strap_speed_table[] = {
	{ .pll = 48, .div = 3, },
	{ .pll = 50, .div = 2, },
	{ .pll = 56, .div = 2, },
	{ .pll = 64, .div = 2, },
	{ .pll = 72, .div = 2, },
	{ .pll = 40, .div = 1, },
	{ .pll = 44, .div = 1, },
	{ .pll = 48, .div = 1, },
};

static const struct taurus_pe_speed taurus_pe_speed_table[] = {
	{ .pll = 64, .div = 2, },
};

static struct taurus_clk_param pll_cpll     = { TAURUS_CLK_PLL, TAURUS_REG_CPLL0 };
static struct taurus_clk_param pll_epll     = { TAURUS_CLK_PLL, TAURUS_REG_EPLL0 };
static struct taurus_clk_param pll_fpll     = { TAURUS_CLK_PLL, TAURUS_REG_FPLL0 };
static struct taurus_clk_param mux_cplldiv  = { TAURUS_CLK_MUX, TAURUS_REG_CPLLDIV };
static struct taurus_clk_param mux_pediv    = { TAURUS_CLK_MUX, TAURUS_REG_PEDIV };
static struct taurus_clk_param div_cplldiv  = { TAURUS_CLK_DIVIDER, TAURUS_REG_CPLLDIV };
static struct taurus_clk_param div_fplldiv  = { TAURUS_CLK_DIVIDER, TAURUS_REG_PEDIV };
static struct taurus_clk_param div_eplldiv  = { TAURUS_CLK_DIVIDER, TAURUS_REG_EPLLDIV };
static struct taurus_clk_param div_eplldiv2 = { TAURUS_CLK_DIVIDER, TAURUS_REG_EPLLDIV2 };
static struct taurus_clk_param gate_config  = { TAURUS_CLK_GATE, TAURUS_REG_GLOBAL_CONFIG };
static struct taurus_clk_param fixed_factor = { TAURUS_CLK_FIXED_FACTOR, 0 };
static struct taurus_clk_param pe_daemon    = { TAURUS_CLK_PE_DAEMON, 0 };
static struct taurus_clk_param cpu_daemon   = { TAURUS_CLK_CPU_DAEMON, 0 };

static const struct of_device_id taurus_soc_clks_ids[] __initconst = {
	{ .compatible = "realtek,taurus-pll-cpll-clk",
	  .data = (void *)&pll_cpll, },
	{ .compatible = "realtek,taurus-pll-fpll-clk",
	  .data = (void *)&pll_fpll, },
	{ .compatible = "realtek,taurus-pll-epll-clk",
	  .data = (void *)&pll_epll, },
	{ .compatible = "realtek,taurus-mux-cpu-clk",
	  .data = (void *)&mux_cplldiv, },
	{ .compatible = "realtek,taurus-mux-pe-clk",
	  .data = (void *)&mux_pediv, },
	{ .compatible = "realtek,taurus-div-cpll-clk",
	  .data = (void *)&div_cplldiv, },
	{ .compatible = "realtek,taurus-div-fpll-clk",
	  .data = (void *)&div_fplldiv, },
	{ .compatible = "realtek,taurus-div-epll-clk",
	  .data = (void *)&div_eplldiv, },
	{ .compatible = "realtek,taurus-div-epll2-clk",
	  .data = (void *)&div_eplldiv2, },
	{ .compatible = "realtek,taurus-gate-clk",
	  .data = (void *)&gate_config, },
	{ .compatible = "realtek,taurus-fixed-factor-clk",
	  .data = (void *)&fixed_factor, },
	{ .compatible = "realtek,taurus-pe-daemon-clk",
	  .data = (void *)&pe_daemon, },
	{ .compatible = "realtek,taurus-cpu-daemon-clk",
	  .data = (void *)&cpu_daemon, },
	{},
};

static bool readonly;

static unsigned long taurus_pll_recalc_rate(struct clk_hw *hw,
					    unsigned long parent_rate)
{
	struct taurus_pll_clk *pll_clk = to_taurus_pll_clk(hw);
	u32 val, divn, prediv;
	u64 result;

	val = (readl(pll_clk->reg) >> TAURUS_DIVN_SHIFT) & clk_mask(TAURUS_DIVN_WIDTH);
	divn = val + TAURUS_DIVN_BASE;

	val = (readl(pll_clk->reg) >> TAURUS_PREDIV_SHIFT) & clk_mask(TAURUS_PREDIV_WIDTH);
	prediv = val + TAURUS_PREDIV_BASE;

	result = (u64)parent_rate * (u64)divn;
	do_div(result, prediv);
	return (unsigned long)result;
}

static long taurus_pll_round_rate(struct clk_hw *hw, unsigned long rate,
				  unsigned long *parent_rate)
{
	unsigned long mult;
	int i;

	if ((rate % (*parent_rate)) != 0)
		goto not_support;

	mult = rate / (*parent_rate);

	for (i = 0; i < ARRAY_SIZE(taurus_pll_param_table); i++) {
		if (taurus_pll_param_table[i].pll == mult)
			return rate;
	}

not_support:
	return *parent_rate;
}

static int taurus_pll_set_rate(struct clk_hw *hw, unsigned long rate,
			       unsigned long parent_rate)
{
	struct taurus_pll_clk *pll_clk = to_taurus_pll_clk(hw);
	unsigned long mult;
	unsigned long flags = 0;
	u32 val, divn, prediv;
	int i;

	if ((rate % parent_rate) != 0)
		return 0;

	mult = rate / parent_rate;
	prediv = 0;
	divn = 0;

	for (i = 0; i < ARRAY_SIZE(taurus_pll_param_table); i++) {
		if (taurus_pll_param_table[i].pll == mult) {
			prediv = taurus_pll_param_table[i].prediv;
			divn = taurus_pll_param_table[i].divn;
		}
	}
	if (mult != (divn / prediv))
		return 0;

	spin_lock_irqsave(pll_clk->lock, flags);
	val = readl(pll_clk->reg);
	val &= ~(clk_mask(TAURUS_DIVN_WIDTH) << TAURUS_DIVN_SHIFT);
	val |= (divn - TAURUS_DIVN_BASE) << TAURUS_DIVN_SHIFT;
	val &= ~(clk_mask(TAURUS_PREDIV_WIDTH) << TAURUS_PREDIV_SHIFT);
	val |= (prediv - TAURUS_PREDIV_BASE) << TAURUS_PREDIV_SHIFT;
	writel(val, pll_clk->reg);
	spin_unlock_irqrestore(pll_clk->lock, flags);

	return rate;
}

static const struct clk_ops taurus_pll_ops = {
	.recalc_rate	= taurus_pll_recalc_rate,
	.round_rate	= taurus_pll_round_rate,
	.set_rate	= taurus_pll_set_rate,
};

static int taurus_clk_pll(struct device_node *np, struct taurus_clk_reg *clk_reg,
			  struct taurus_clk_param *clk_param)
{
	const char *parent_name;
	void __iomem *reg;
	struct clk_init_data init;
	struct taurus_pll_clk *pll_clk;
	struct clk *soc_clk;

	parent_name = of_clk_get_parent_name(np, 0);
	reg = clk_reg->regbase + clk_param->reg;

	pll_clk = kzalloc(sizeof(*pll_clk), GFP_KERNEL);
	if (!pll_clk)
		return -ENOMEM;

	init.name = np->name;
	init.ops = &taurus_pll_ops;
	init.parent_names = (parent_name ? &parent_name : NULL);
	init.num_parents = (parent_name ? 1 : 0);
	init.flags = 0;

	pll_clk->hw.init = &init;
	pll_clk->reg = reg;
	pll_clk->lock = &clk_reg->regs_lock;

	soc_clk = clk_register(NULL, &pll_clk->hw);
	if (!IS_ERR(soc_clk))
		of_clk_add_provider(np, of_clk_src_simple_get, soc_clk);
	else
		kfree(pll_clk);

	return IS_ERR(soc_clk) ? PTR_ERR(soc_clk) : 0;
}

static int taurus_clk_divider(struct device_node *np, struct taurus_clk_reg *clk_reg,
			      struct taurus_clk_param *clk_param)
{
	u8 op_shift, op_width;
	u8 init_div = 0;
	u32 val;
	unsigned long flags = 0;
	const char *parent_name;
	void __iomem *reg;
	struct clk *soc_clk;

	if (of_property_read_u8(np, "operate-shift", &op_shift))
		return -EPERM;
	if (op_shift >= 32)
		return -EINVAL;
	if (of_property_read_u8(np, "operate-width", &op_width))
		return -EPERM;
	if (op_width >= 32)
		return -EINVAL;

	parent_name = of_clk_get_parent_name(np, 0);
	reg = clk_reg->regbase + clk_param->reg;

	if (of_property_read_u8(np, "init-div", &init_div))
		init_div = 0;

	if (init_div) {
		spin_lock_irqsave(&clk_reg->regs_lock, flags);

		val = readl(reg);
		val &= ~(clk_mask(op_width) << op_shift);
		val |= (init_div << 1) << op_shift;
		writel(val, reg);

		spin_unlock_irqrestore(&clk_reg->regs_lock, flags);
	}

	soc_clk = clk_register_divider(NULL, np->name, parent_name, 0,
				       reg, op_shift + 1, op_width - 1,
				       CLK_DIVIDER_ONE_BASED |
				       CLK_DIVIDER_ALLOW_ZERO,
				       &clk_reg->regs_lock);

	if (!IS_ERR(soc_clk))
		of_clk_add_provider(np, of_clk_src_simple_get, soc_clk);

	return IS_ERR(soc_clk) ? PTR_ERR(soc_clk) : 0;
}

static int taurus_clk_mux(struct device_node *np, struct taurus_clk_reg *clk_reg,
			  struct taurus_clk_param *clk_param)
{
	u8 op_shift, num_parents;
	void __iomem *reg;
	const char *parent_names[2];
	struct clk *soc_clk;
	int i;

	if (of_property_read_u8(np, "operate-shift", &op_shift))
		return -EPERM;
	if (op_shift >= 32)
		return -EINVAL;
	num_parents = of_clk_get_parent_count(np);
	if (num_parents != 2)
		return -EINVAL;

	for (i = 0; i < num_parents; i++)
		parent_names[i] = of_clk_get_parent_name(np, i);

	reg = clk_reg->regbase + clk_param->reg;

	soc_clk = clk_register_mux(NULL, np->name, parent_names, num_parents,
				   0, reg, op_shift, 1, 0, &clk_reg->regs_lock);
	if (!IS_ERR(soc_clk))
		of_clk_add_provider(np, of_clk_src_simple_get, soc_clk);

	return IS_ERR(soc_clk) ? PTR_ERR(soc_clk) : 0;
}

static int taurus_clk_gate(struct device_node *np, struct taurus_clk_reg *clk_reg,
			   struct taurus_clk_param *clk_param)
{
	u8 op_shift, gate_flags;
	void __iomem *reg;
	struct clk *soc_clk;

	if (of_property_read_u8(np, "operate-shift", &op_shift))
		return -EPERM;
	if (op_shift >= 32)
		return -EINVAL;

	if (of_property_read_bool(np, "active-low"))
		gate_flags = CLK_GATE_SET_TO_DISABLE;
	else
		gate_flags = 0;

	reg = clk_reg->regbase + clk_param->reg;

	soc_clk = clk_register_gate(NULL, np->name, NULL, 0, reg, op_shift,
				    gate_flags, &clk_reg->regs_lock);
	if (!IS_ERR(soc_clk))
		of_clk_add_provider(np, of_clk_src_simple_get, soc_clk);

	return IS_ERR(soc_clk) ? PTR_ERR(soc_clk) : 0;
}

static int taurus_clk_fixed_factor(struct device_node *np,
				   struct taurus_clk_reg *clk_reg,
				   struct taurus_clk_param *clk_param)
{
	unsigned int mult, div;
	const char *parent_name;
	struct clk *soc_clk;

	if (of_property_read_u32(np, "fixed-mult", &mult))
		mult = 1;
	if (of_property_read_u32(np, "fixed-div", &div))
		div = 1;

	parent_name = of_clk_get_parent_name(np, 0);

	soc_clk = clk_register_fixed_factor(NULL, np->name, parent_name, 0,
					    mult, div);
	if (!IS_ERR(soc_clk))
		of_clk_add_provider(np, of_clk_src_simple_get, soc_clk);

	return IS_ERR(soc_clk) ? PTR_ERR(soc_clk) : 0;
}

static int taurus_clk_pe_daemon(struct device_node *np,
				struct taurus_clk_reg *clk_reg,
				struct taurus_clk_param *clk_param)
{
	return 0;
}

static unsigned long taurus_cpu_recalc_rate(struct clk_hw *hw,
					    unsigned long parent_rate)
{
	struct taurus_cpu_daemon *cpud = to_taurus_cpu_daemon(hw);
	unsigned long ref_rate;
	u32 cpll0, cplldiv;
	void __iomem *cpll0_reg;
	void __iomem *cplldiv_reg;
	u8 prediv, mult, div;
	u64 result;

	cpll0_reg = cpud->reg + TAURUS_REG_CPLL0;
	cplldiv_reg = cpud->reg + TAURUS_REG_CPLLDIV;

	cpll0 = readl(cpll0_reg);
	cplldiv = readl(cplldiv_reg);
	mult = (cpll0 & clk_mask(TAURUS_DIVN_WIDTH)) + TAURUS_DIVN_BASE;
	prediv = ((cpll0 >> TAURUS_PREDIV_SHIFT) & clk_mask(TAURUS_PREDIV_WIDTH)) +
		 TAURUS_PREDIV_BASE;
	div = (cplldiv & clk_mask(TAURUS_CPLLDIV_CORTEX_WIDTH)) >> 1;

	if (div == 0)
		div = 1;

	ref_rate = clk_get_rate(cpud->clks[TAURUS_CPUD_REF]);
	result = (u64)ref_rate * (u64)mult;
	do_div(result, prediv);
	do_div(result, div);

	return (unsigned long)result;
}

static long taurus_cpu_round_rate(struct clk_hw *hw, unsigned long rate,
				  unsigned long *parent_rate)
{
	struct taurus_cpu_daemon *cpud = to_taurus_cpu_daemon(hw);
	unsigned long ref_rate, target;
	u32 mult, div;
	int i;

	ref_rate = clk_get_rate(cpud->clks[TAURUS_CPUD_REF]);
	for (i = 0; i < ARRAY_SIZE(taurus_cpu_strap_speed_table); i++) {
		mult = taurus_cpu_strap_speed_table[i].pll;
		div = taurus_cpu_strap_speed_table[i].div;
		target = ref_rate * mult / div;
		if (rate == target)
			return target;
	}

	return *parent_rate;
}

static int taurus_cpu_set_rate(struct clk_hw *hw, unsigned long rate,
			       unsigned long parent_rate)
{
	struct taurus_cpu_daemon *cpud = to_taurus_cpu_daemon(hw);
	u32 cpll0, cplldiv;
	void __iomem *reg;
	unsigned long ref_rate;
	unsigned long long target;
	u32 mult, div;
	unsigned long flags = 0;
	int i;

	if (readonly)
		return 0;

	ref_rate = clk_get_rate(cpud->clks[TAURUS_CPUD_REF]);
	mult = 0;
	div = 0;
	for (i = 0; i < ARRAY_SIZE(taurus_cpu_strap_speed_table); i++) {
		u32 t_mult = taurus_cpu_strap_speed_table[i].pll;
		u32 t_div = taurus_cpu_strap_speed_table[i].div;

		target = (u64)ref_rate * (u64)t_mult;
		do_div(target, t_div);
		if (rate == target) {
			mult = t_mult;
			div = t_div;
			break;
		}
	}

	if (mult == 0)
		return 0;

	mutex_lock(&cpud->mlock);

	clk_set_parent(hw->clk, NULL);

	clk_set_parent(cpud->clks[TAURUS_CPUD_MUX_CPU], cpud->clks[TAURUS_CPUD_DIV_F2C]);

	spin_lock_irqsave(cpud->lock, flags);
	reg = cpud->reg + TAURUS_REG_CPLL0;
	cpll0 = readl(reg);
	cpll0 &= ~(clk_mask(TAURUS_CPLL_RSTB_WIDTH) << TAURUS_CPLL_RSTB_SHIFT);
	writel(cpll0, reg);
	spin_unlock_irqrestore(cpud->lock, flags);

	clk_set_rate(cpud->clks[TAURUS_CPUD_CPLL], ref_rate * mult);

	spin_lock_irqsave(cpud->lock, flags);
	reg = cpud->reg + TAURUS_REG_CPLLDIV;
	cplldiv = readl(reg);
	cplldiv |= BIT(TAURUS_CPLLDIV_MODE_OVERRIDE);
	writel(cplldiv, reg);
	spin_unlock_irqrestore(cpud->lock, flags);

	spin_lock_irqsave(cpud->lock, flags);
	reg = cpud->reg + TAURUS_REG_CPLL0;
	cpll0 = readl(reg);
	cpll0 |= BIT(TAURUS_CPLL_RSTB_SHIFT);
	writel(cpll0, reg);
	spin_unlock_irqrestore(cpud->lock, flags);
	udelay(TAURUS_DELAY_PLL_FOR_LOCK);

	spin_lock_irqsave(cpud->lock, flags);
	reg = cpud->reg + TAURUS_REG_CPLLDIV;
	cplldiv = readl(reg);
	cplldiv &= ~clk_mask(TAURUS_CPLLDIV_CORTEX_WIDTH);
	cplldiv |= (div << 1);
	cplldiv |= BIT(TAURUS_CPLLDIV_OVERRIDE);
	writel(cplldiv, reg);
	spin_unlock_irqrestore(cpud->lock, flags);

	clk_set_parent(cpud->clks[TAURUS_CPUD_MUX_CPU], cpud->clks[TAURUS_CPUD_CPLL]);

	clk_set_parent(hw->clk, cpud->clks[TAURUS_CPUD_DIV_CORTEX]);

	mutex_unlock(&cpud->mlock);

	pr_info("taurus-clk: change CPU frequency to %lu MHz\n", rate / 1000000);

	return rate;
}

static int taurus_cpu_init(struct clk_hw *hw)
{
	struct taurus_cpu_daemon *cpud = to_taurus_cpu_daemon(hw);
	void __iomem *cpllmux_reg;

	cpllmux_reg = cpud->reg + TAURUS_REG_CPLLMUX;

	writel(TAURUS_CPLLMUX_MAGIC, cpllmux_reg);
	return 0;
}

static const struct clk_ops taurus_cpu_ops = {
	.recalc_rate	= taurus_cpu_recalc_rate,
	.round_rate	= taurus_cpu_round_rate,
	.set_rate	= taurus_cpu_set_rate,
	.init		= taurus_cpu_init,
};

static int taurus_clk_cpu_daemon(struct device_node *np,
				 struct taurus_clk_reg *clk_reg,
				 struct taurus_clk_param *clk_param)
{
	const char *parent_names[TAURUS_CPUD_CLKS_NUM];
	unsigned long ref_rate, min_rate, max_rate;
	int i;
	struct clk *cpu_clk;
	void __iomem *reg;
	int strap;
	u32 cplldiv;
	unsigned long mult, div;
	u64 rate;
	struct clk_init_data init;
	struct taurus_cpu_daemon *cpud;

	readonly = of_property_read_bool(np, "read-only");

	cpud = kzalloc(sizeof(*cpud), GFP_KERNEL);
	if (!cpud)
		return -ENOMEM;

	for (i = 0; i < TAURUS_CPUD_CLKS_NUM; i++) {
		cpud->clks[i] = of_clk_get(np, i);
		if (IS_ERR(cpud->clks[i])) {
			int ret = PTR_ERR(cpud->clks[i]);

			kfree(cpud);
			return ret;
		}
		parent_names[i] = __clk_get_name(cpud->clks[i]);
	}

	ref_rate = clk_get_rate(cpud->clks[TAURUS_CPUD_REF]);
	min_rate = ref_rate * taurus_cpu_strap_speed_table[0].pll /
		   taurus_cpu_strap_speed_table[0].div;
	max_rate = ref_rate * taurus_cpu_strap_speed_table[7].pll /
		   taurus_cpu_strap_speed_table[7].div;

	reg = clk_reg->regbase + TAURUS_REG_CPLLDIV;
	cplldiv = readl(reg);
	if (cplldiv & BIT(TAURUS_CPLLDIV_MODE_OVERRIDE)) {
		pr_info("taurus-clk: CPLL clock has been initialized, skip CPLL init\n");
	} else {
		reg = clk_reg->regbase + TAURUS_REG_STRAP;
		strap = (readl(reg) >> TAURUS_STRAP_SPEED_SHIFT) &
			clk_mask(TAURUS_STRAP_SPEED_WIDTH);
		mult = taurus_cpu_strap_speed_table[strap].pll;
		div = taurus_cpu_strap_speed_table[strap].div;
		rate = (u64)ref_rate * (u64)mult / div;

		clk_set_rate(cpud->clks[TAURUS_CPUD_CPLL], ref_rate * mult);
		rate = clk_get_rate(cpud->clks[TAURUS_CPUD_MUX_CPU]) / div + 1;
		clk_set_rate(cpud->clks[TAURUS_CPUD_DIV_CORTEX], rate);
	}

	init.name = np->name;
	init.ops = &taurus_cpu_ops;
	init.parent_names = &parent_names[TAURUS_CPUD_DIV_CORTEX];
	init.num_parents = 1;
	init.flags = 0;

	mutex_init(&cpud->mlock);
	cpud->reg = clk_reg->regbase;
	cpud->lock = &clk_reg->regs_lock;
	cpud->hw.init = &init;

	cpu_clk = clk_register(NULL, &cpud->hw);
	if (!IS_ERR(cpu_clk)) {
		of_clk_add_provider(np, of_clk_src_simple_get, cpu_clk);
		clk_set_min_rate(cpu_clk, min_rate);
		clk_set_max_rate(cpu_clk, max_rate);
	} else {
		for (i = 0; i < TAURUS_CPUD_CLKS_NUM; i++)
			clk_put(cpud->clks[i]);
		kfree(cpud);
	}

	return IS_ERR(cpu_clk) ? PTR_ERR(cpu_clk) : 0;
}

static int (*taurus_clk_setup_fns[])(struct device_node *np,
				     struct taurus_clk_reg *clk_reg,
				     struct taurus_clk_param *clk_param) = {
	[TAURUS_CLK_PLL]		= taurus_clk_pll,
	[TAURUS_CLK_DIVIDER]		= taurus_clk_divider,
	[TAURUS_CLK_MUX]		= taurus_clk_mux,
	[TAURUS_CLK_GATE]		= taurus_clk_gate,
	[TAURUS_CLK_FIXED_FACTOR]	= taurus_clk_fixed_factor,
	[TAURUS_CLK_PE_DAEMON]		= taurus_clk_pe_daemon,
	[TAURUS_CLK_CPU_DAEMON]		= taurus_clk_cpu_daemon,
};

static void __init taurus_soc_clks_setup(struct device_node *np)
{
	struct device_node *childnp;
	const struct of_device_id *clk_id;
	struct taurus_clk_param *clk_param;
	struct taurus_clk_reg *soc_clk_reg;

	soc_clk_reg = kzalloc(sizeof(*soc_clk_reg), GFP_KERNEL);
	if (!soc_clk_reg)
		return;

	soc_clk_reg->regbase = of_iomap(np, 0);
	if (!soc_clk_reg->regbase) {
		kfree(soc_clk_reg);
		return;
	}
	spin_lock_init(&soc_clk_reg->regs_lock);

	for_each_child_of_node(np, childnp) {
		clk_id = of_match_node(taurus_soc_clks_ids, childnp);
		if (!clk_id)
			continue;

		clk_param = (struct taurus_clk_param *)clk_id->data;
		if (taurus_clk_setup_fns[clk_param->type](childnp, soc_clk_reg,
							  clk_param))
			pr_err("taurus-clk: setup(%s) failed\n", childnp->name);
	}

	pr_info("taurus-clk: soc clks setup finished\n");
}
CLK_OF_DECLARE(taurus_soc_clks, "realtek,taurus-soc-clks", taurus_soc_clks_setup);
