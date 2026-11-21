'use strict';
'require baseclass';
'require rpc';

var callStatus = rpc.declare({ object: 'luci.rtl9617c-pon', method: 'status', expect: { '': {} }, reject: true });
var modes = {
	epon: 'EPON', 'epon-d10g': '10G EPON（非对称）', 'epon-bi10g': '10G EPON（对称）',
	gpon: 'GPON', xgpon: 'XG-PON', xgspon: 'XGS-PON'
};

function value(v) { return v == null || v === '' ? '—' : String(v); }
function flag(v) { return v === '1' || v === 1 || v === true; }
function s16(raw) {
	var n = Number(raw);
	return isFinite(n) && (n & 0x8000) ? n - 0x10000 : n;
}
function temperature(data) {
	var raw = (data || {}).temperature_raw;
	if (raw == null || raw === '') return '—';
	return (s16(raw) / 256).toFixed(1) + ' °C';
}
function voltage(data) {
	var raw = Number((data || {}).voltage_raw);
	return isFinite(raw) && raw > 0 ? (raw * 100e-6).toFixed(3) + ' V' : '—';
}
function bias(data) {
	var raw = Number((data || {}).bias_raw);
	return isFinite(raw) && raw > 0 ? (raw * 2e-3).toFixed(2) + ' mA' : '—';
}
function power(raw) {
	var n = Number(raw);
	if (!isFinite(n) || n <= 0) return '—';
	return (10 * Math.log10(n * 0.1e-3)).toFixed(2) + ' dBm';
}
function opticalRows(data) {
	var t = (data || {}).transceiver || {};
	return [['温度', temperature(t)], ['电压', voltage(t)],
		['Tx 偏置', bias(t)], ['Tx 光功率', power(t.tx_power_raw)],
		['Rx 光功率', power(t.rx_power_raw)]];
}
function bosaName(bosa) {
	if (!bosa) return '—';
	if (bosa.identity) {
		var text = bosa.identity.split('/').map(function(hex) {
			return String.fromCharCode(parseInt(hex, 16));
		}).join('');
		if (/^[\x20-\x7e]{2,}$/.test(text)) return text;
	}
	return value(bosa.model);
}
function badge(text, tone) { return E('span', { class: 'tyf-badge tyf-' + (tone || 'muted') }, [text]); }
function rows(items) {
	return E('dl', { class: 'tyf-facts' }, items.reduce(function(nodes, item) {
		return nodes.concat([E('dt', {}, [item[0]]), E('dd', {}, [item[1] == null ? '—' : item[1]])]);
	}, []));
}
function card(title, state, content) {
	return E('section', { class: 'tyf-card' }, [E('div', { class: 'tyf-card-head' }, [E('h3', {}, [title]), state])].concat(content == null ? [] : content));
}
function omciLive(data) {
	var omci = data.omci, path = data.data_path || {};
	return !!(omci && omci.live && (omci.session == null || path.session == null || String(omci.session) === String(path.session)));
}
function ponState(data) {
	var serdes = data.serdes || {}, mac = data.mac || {}, mpcp = data.mpcp || {};
	if (data.service && data.service.enabled === '0')
		return { text: '未启用', tone: 'muted' };
	var failed = ['service', 'activation', 'bosa', 'serdes', 'mac', 'mpcp'].find(function(name) {
		return data[name] && data[name].error != null && +data[name].error !== 0;
	});
	if (failed)
		return { text: '初始化异常', tone: 'danger', help: failed + ' 错误码：' + data[failed].error + '。请查看高级诊断和系统日志。' };
	if (flag((data.optical || {}).tx_fault))
		return { text: '光模块发射故障', tone: 'danger', help: '光模块报告 TX Fault，请检查高级诊断。' };
	if (flag((data.optical || {}).rx_los) || flag(serdes.rx_los))
		return { text: '接收失光', tone: 'danger', help: '未检测到接收光信号，请检查光纤与上联线路。' };
	if (!modes[serdes.mode] || serdes.configured == null)
		return { text: '状态不可用', tone: 'muted', help: '驱动尚未提供有效线路状态，请查看系统日志。' };
	if (serdes.configured === '0' || mac.enabled === '0' || /^epon/.test(serdes.mode) && mpcp.enabled === '0')
		return { text: '未启用', tone: 'muted' };
	if (/^(gpon|xgpon|xgspon)$/.test(serdes.mode)) {
		var businessError = ['data_path', 'omci'].find(function(name) {
			return data[name] && (name !== 'omci' || omciLive(data)) && data[name].error != null && +data[name].error !== 0;
		});
		if (businessError)
			return { text: '业务配置异常', tone: 'danger', help: businessError + ' 错误码：' + data[businessError].error + '。请查看高级诊断。' };
		if (!omciLive(data))
			return { text: 'OMCI 状态不可用', tone: 'danger', help: '未取得存活控制进程的最新状态；历史数据保留在高级诊断中，请检查系统日志。' };
		if (+data.omci.auth > 1)
			return { text: '认证未通过', tone: 'danger', help: 'OLT 返回 LOID 认证状态码：' + data.omci.auth + '。请核对运营商认证参数。' };
		return mac.activation === 'O5' && flag(mac.prepared)
			? flag((data.data_path || {}).configured)
				? { text: '已激活 · 业务已配置', tone: 'good' }
				: { text: '已激活 · 等待业务下发', tone: 'warn' }
			: { text: '等待激活', tone: 'warn', help: '激活状态：' + value(mac.activation) };
	}
	if (!flag(mpcp.enabled) || !/^[0-9a-f]+$/i.test(mpcp.registered || '') || !parseInt(mpcp.registered, 16))
		return { text: '等待注册', tone: 'warn' };
	var ports = (data.oam_ports || []).filter(function(p) { return p.live && p.registered; });
	var rejected = ports.find(function(p) { return p.auth_state === 'rejected'; });
	if (rejected)
		return { text: '认证未通过', tone: 'danger', help: rejected.auth_mode === 'loid' ? 'OLT 拒绝 LOID 认证，请核对 LOID 和密码。' : 'OLT 拒绝认证，请核对 ONU MAC 地址或运营商认证参数。' };
	var accepted = ports.find(function(p) { return p.auth_state === 'accepted' && p.discovery_stable; });
	if (accepted)
		return accepted.auth_source === 'ctc-result'
			? { text: '已注册 · OLT 认证通过', tone: 'good', help: 'OLT 已返回 CTC 认证通过结果；若运营商在业务层校验 MAC/账号，请同时确认 WAN 拨号或业务通道状态。' }
			: { text: '已注册 · OLT 配置已下发', tone: 'good', help: 'OLT 已完成 OAM 发现与 CTC 业务配置下发（原厂判据视为 OLT 注册成功）；部分运营商不在 OLT OAM 层拦截未备案 MAC，而在上层 VLAN/BRAS 放行数据，请以 WAN 拨号连通为准。' };
	return { text: '已注册 · 等待认证', tone: 'warn' };
}

function ponCard(data) {
	var state = ponState(data), optical = data.optical || {}, serdes = data.serdes || {};
	var los = flag(serdes.rx_los) || flag(optical.rx_los) ? '接收失光' :
		serdes.rx_los != null || optical.rx_los != null ? '未失光' : '未提供';
	return E('section', { class: 'tyf-link-panel', 'data-tone': state.tone }, [
		E('div', { class: 'tyf-link-state' }, [
			E('p', { class: 'tyf-eyebrow' }, 'PON / 实时光链路'),
			E('h3', {}, [E('span', { class: 'tyf-state-dot', 'aria-hidden': 'true' }), state.text]),
			E('p', { class: 'tyf-note' }, state.help || '线路注册与认证不等同于互联网连通，请在接口管理中确认 WAN 状态。')]),
		E('div', { class: 'tyf-link-facts' }, rows([
			['运行协议', modes[serdes.mode] || value(serdes.mode)],
			['接收光信号', los],
			['发射告警', optical.tx_fault == null ? '未提供' : flag(optical.tx_fault) ? '发射故障' : '无发射故障']
		].concat(opticalRows(data))))
	]);
}

var SVG_NS = 'http://www.w3.org/2000/svg';
var offloadSample = null;
var shortModes = {
	epon: 'EPON', 'epon-d10g': '10G EPON', 'epon-bi10g': '10G 对称',
	gpon: 'GPON', xgpon: 'XG-PON', xgspon: 'XGS-PON'
};

function svgEl(tag, attrs, children) {
	var el = document.createElementNS(SVG_NS, tag);
	if (attrs) {
		Object.keys(attrs).forEach(function(k) {
			if (attrs[k] != null)
				el.setAttribute(k, String(attrs[k]));
		});
	}
	if (children != null) {
		(Array.isArray(children) ? children : [children]).forEach(function(child) {
			if (child == null)
				return;
			el.appendChild(typeof child === 'string' || typeof child === 'number'
				? document.createTextNode(String(child))
				: child);
		});
	}
	return el;
}

function formatRate(bps) {
	if (bps == null || !isFinite(bps) || bps < 0)
		return null;
	var units = ['B/s', 'KiB/s', 'MiB/s', 'GiB/s'];
	var v = bps, i = 0;
	while (v >= 1024 && i < units.length - 1) {
		v /= 1024;
		i++;
	}
	return v.toFixed(i ? 1 : 0) + ' ' + units[i];
}

function formatBytes(bytes) {
	if (bytes == null || !isFinite(bytes))
		return '—';
	var units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
	var v = Number(bytes), i = 0;
	while (v >= 1024 && i < units.length - 1) {
		v /= 1024;
		i++;
	}
	return v.toFixed(i ? 1 : 0) + ' ' + units[i];
}

function flowSpeedCls(bps, hasFlows, active) {
	if (!active)
		return 'is-off';
	if (bps != null && bps >= 5 * 1024 * 1024)
		return 'is-fast';
	if (bps != null && bps >= 256 * 1024)
		return 'is-med';
	return (hasFlows || (bps != null && bps > 128)) ? 'is-slow' : 'is-idle';
}

function durationForSpeed(cls) {
	return cls === 'is-fast' ? 850 : cls === 'is-med' ? 1300 : cls === 'is-slow' ? 2000 : 0;
}

function phaseStyle(ms) {
	if (!ms)
		return null;
	var delay = -(Date.now() % ms);
	return 'animation-duration:' + ms + 'ms;animation-delay:' + delay + 'ms';
}

function sampleRates(data) {
	var ponPort = (data.ports || []).find(function(p) { return p.device === 'pon0'; });
	var pStats = (ponPort && ponPort.statistics) || {};
	var nowMs = data.uptime_ms != null ? Number(data.uptime_ms) : Date.now();
	var fp = data.fe_paths || {};
	var up = fp.upstream || {}, down = fp.downstream || {};
	var curr = {
		ts: nowMs,
		ponTx: pStats.tx_bytes == null ? null : Number(pStats.tx_bytes),
		ponRx: pStats.rx_bytes == null ? null : Number(pStats.rx_bytes),
		feUp: up.bytes == null ? null : Number(up.bytes),
		feDown: down.bytes == null ? null : Number(down.bytes),
		rates: offloadSample ? offloadSample.rates : { ponTxBps: null, ponRxBps: null, feUpBps: null, feDownBps: null }
	};
	if (offloadSample && nowMs !== offloadSample.ts) {
		var dt = (nowMs - offloadSample.ts) / 1000;
		if (dt >= 0.4 && dt <= 120) {
			function diffRate(a, b) {
				return (a != null && b != null && a >= b) ? (a - b) / dt : null;
			}
			curr.rates = {
				ponTxBps: diffRate(curr.ponTx, offloadSample.ponTx),
				ponRxBps: diffRate(curr.ponRx, offloadSample.ponRx),
				feUpBps: diffRate(curr.feUp, offloadSample.feUp),
				feDownBps: diffRate(curr.feDown, offloadSample.feDown)
			};
		}
		offloadSample = curr;
	} else if (!offloadSample) {
		offloadSample = curr;
	}
	return curr.rates;
}

function lanSummary(data, fePaths) {
	var ports = (data.ports || []).filter(function(p) { return /^lan/.test(p.device || ''); });
	var upPorts = ports.filter(function(p) { return p.present && p.carrier === '1'; });
	var portMap = (fePaths && fePaths.ports) || {};
	var topLine = '未连接', subLine = '无物理连接';

	if (upPorts.length === 1) {
		var p = upPorts[0];
		var spd = Number(p.speed) > 0 ? (Number(p.speed) >= 1000 ? (Number(p.speed) / 1000).toFixed(Number(p.speed) % 1000 ? 1 : 0) + 'G' : p.speed + 'M') : '已连';
		topLine = p.device + ' · ' + spd;
	} else if (upPorts.length > 1) {
		topLine = '已连 ' + upPorts.length + ' 口';
	}

	var activeLan = Object.keys(portMap);
	if (activeLan.length) {
		var first = activeLan[0], stat = portMap[first];
		subLine = first + ' ↑' + stat.up + ' ↓' + stat.down;
		if (activeLan.length > 1)
			subLine += ' (+' + (activeLan.length - 1) + ')';
	} else if (upPorts.length) {
		subLine = upPorts.map(function(p) { return p.device; }).slice(0, 2).join(' · ');
	}
	return { top: topLine, sub: subLine, upCount: upPorts.length };
}

function conduitTrack(dirCls, speedCls, label) {
	var ms = durationForSpeed(speedCls);
	var style = phaseStyle(ms);
	return E('div', { class: 'tyf-fe-track ' + dirCls + ' ' + speedCls }, [
		label ? E('span', { class: 'tyf-fe-track-lbl' }, [label]) : null,
		E('div', { class: 'tyf-fe-rail-line' }, [
			E('span', { class: 'tyf-fe-rail-track' }, [
				ms ? E('span', { class: 'tyf-fe-comet', style: style }) : null
			]),
			E('span', { class: 'tyf-fe-arrow-tip' })
		])
	]);
}

function verticalConduit(dirCls, colorCls, speedCls) {
	var ms = durationForSpeed(speedCls);
	var style = phaseStyle(ms);
	return E('div', { class: 'tyf-fe-vtrack ' + dirCls + ' ' + colorCls + ' ' + speedCls }, [
		E('span', { class: 'tyf-fe-vrail' }, [
			ms ? E('span', { class: 'tyf-fe-vcomet', style: style }) : null
		]),
		E('span', { class: 'tyf-fe-varrow' })
	]);
}

function cpuBridgeSvg(cpuCls, ms) {
	var svg = svgEl('svg', {
		class: 'tyf-fe-cpu-svg ' + cpuCls,
		viewBox: '0 0 600 44',
		preserveAspectRatio: 'none',
		'aria-hidden': 'true'
	});
	var style = phaseStyle(ms);
	['M 160 44 C 160 16, 188 12, 228 12', 'M 372 12 C 412 12, 440 16, 440 44'].forEach(function(d) {
		svg.appendChild(svgEl('path', { d: d, class: 'tyf-fe-cpu-rail' }));
		if (ms)
			svg.appendChild(svgEl('path', { d: d, class: 'tyf-fe-cpu-flow', style: style }));
	});
	return svg;
}

function offloadDiagram(data, software, hardware, fe, rates) {
	var available = flag(fe.available), enabled = flag(fe.enabled);
	var hwError = fe.error != null && Number(fe.error) !== 0;
	var hwReady = software && hardware && available && enabled && !hwError;
	var flows = Number(fe.flows || 0);
	var hashEntries = Number(fe.hash_entries || 65536);
	var fp = data.fe_paths || null;
	var upFlows = fp && fp.upstream ? Number(fp.upstream.flows || 0) : null;
	var downFlows = fp && fp.downstream ? Number(fp.downstream.flows || 0) : null;
	var hasUp = upFlows != null ? upFlows > 0 : flows > 0;
	var hasDown = downFlows != null ? downFlows > 0 : flows > 0;

	var upSpeed = flowSpeedCls(rates.ponTxBps, hasUp, hwReady);
	var downSpeed = flowSpeedCls(rates.ponRxBps, hasDown, hwReady);
	var cpuCls = hwReady ? 'is-subtle' : 'is-active';
	var cpuMs = hwReady ? 3200 : 1650;

	var lanInfo = lanSummary(data, fp);
	var serdes = data.serdes || {};
	var ponPort = (data.ports || []).find(function(p) { return p.device === 'pon0'; }) || {};
	var ponProto = shortModes[serdes.mode] || value(serdes.mode);
	var ponAttach = flag(fe.pon_attached) ? '已挂载 FE' : '未挂载 FE';
	var ponUp = ponPort.present && ponPort.carrier === '1';

	var cpuSub = hwReady ? '首包建流写入 FE · 代理/未卸载慢路径' : software ? '仅软件 Flowtable（经 CPU 转发）' : '普通内核转发（经 CPU 转发）';
	var feStateCls = !software || !hardware ? 'is-muted' : (!available || !enabled || hwError) ? 'is-danger' : 'is-good';
	var feStatLine = !software ? '未开启' : !hardware ? '硬件旁路' :
		hwError ? ('异常 ' + fe.error) :
		!available ? '不可用' :
		!enabled ? '未启用' :
		(flows + ' / ' + hashEntries.toLocaleString() + ' 流');
	var pct = hashEntries > 0 ? Math.min(100, Math.max(flows > 0 ? 4 : 0, (flows / hashEntries) * 100)) : 0;

	var upLabel = upFlows != null ? ('↑ ' + upFlows + '流') : '↑ 上行';
	var downLabel = downFlows != null ? ('↓ ' + downFlows + '流') : '↓ 下行';
	var bindStyle = phaseStyle(hwReady ? 2100 : 0);
	var cSlots = Number(fe.counter_slots || 32);
	var cUsed = Number(fe.counted_flows || 0);
	var slotPct = cSlots > 0 ? Math.min(100, Math.max(cUsed > 0 ? 4 : 0, (cUsed / cSlots) * 100)) : 0;
	var qmPct = hwReady ? (flag(fe.pon_attached) ? 100 : 50) : 0;
	var slotInfo = fe.counted_flows != null && fe.counter_slots != null ? ('计数槽 ' + fe.counted_flows + '/' + fe.counter_slots) : 'NAT·PPPoE';

	return E('div', { class: 'tyf-fe-visual' }, [
		E('div', { class: 'tyf-fe-scroll' }, [
			E('div', { class: 'tyf-fe-board' }, [
				E('div', { class: 'tyf-fe-top-row' }, [
					cpuBridgeSvg(cpuCls, cpuMs),
					E('div', { class: 'tyf-fe-cpu-pill ' + cpuCls }, [
						E('span', { class: 'tyf-fe-cpu-name' }, 'CPU · Linux Netfilter'),
						E('span', { class: 'tyf-fe-cpu-desc' }, cpuSub)
					]),
					E('div', { class: 'tyf-fe-top-links' }, [
						E('span', { class: 'tyf-fe-top-tag' }, hwReady ? '慢路径 DMA 收包' : 'CPU 收包'),
						E('div', { class: 'tyf-fe-bind ' + (hwReady ? 'is-active' : 'is-muted') }, [
							E('span', { class: 'tyf-fe-bind-line' }, [
								hwReady ? E('span', { class: 'tyf-fe-bind-dot', style: bindStyle }) : null
							]),
							E('span', { class: 'tyf-fe-bind-txt' }, hwReady ? '下发流表到 FE' : '未开启硬卸载')
						]),
						E('span', { class: 'tyf-fe-top-tag' }, hwReady ? '慢路径调度发送' : 'CPU 发包')
					])
				]),
				E('div', { class: 'tyf-fe-arch-grid' }, [
					E('div', { class: 'tyf-fe-node tyf-fe-endpoint ' + (lanInfo.upCount ? 'is-up' : '') }, [
						E('div', { class: 'tyf-fe-node-head' }, [E('i', { class: 'tyf-fe-ndot' }), 'LAN 端口']),
						E('div', { class: 'tyf-fe-node-val' }, lanInfo.top),
						E('div', { class: 'tyf-fe-node-sub' }, lanInfo.sub)
					]),
					E('div', { class: 'tyf-fe-conduit' }, [
						conduitTrack('is-up is-ltr', upSpeed, upLabel),
						conduitTrack('is-down is-rtl', downSpeed, '← LAN')
					]),
					E('div', { class: 'tyf-fe-soc ' + feStateCls }, [
						E('div', { class: 'tyf-fe-soc-head' }, [
							E('span', { class: 'tyf-fe-soc-title' }, 'RTL9617C 硬件卸载引擎内部通路'),
							E('span', { class: 'tyf-fe-core-chip' }, hwReady ? '绕过 CPU 直通' : '引擎旁路')
						]),
						E('div', { class: 'tyf-fe-core-row' }, [
							E('div', { class: 'tyf-fe-mod is-fe ' + feStateCls }, [
								E('div', { class: 'tyf-fe-mod-top' }, [
									E('span', { class: 'tyf-fe-mod-name' }, 'FE 转发引擎'),
									E('span', { class: 'tyf-fe-mod-tag' }, 'L2/L3')
								]),
								E('div', { class: 'tyf-fe-mod-sub' }, '64K Hash 流表查表'),
								E('div', { class: 'tyf-fe-cap-bar' }, [
									E('span', { class: 'tyf-fe-cap-fill ' + feStateCls, style: 'width:' + pct.toFixed(1) + '%' })
								]),
								E('div', { class: 'tyf-fe-mod-meta' }, feStatLine)
							]),
							E('div', { class: 'tyf-fe-dual-link' }, [
								conduitTrack('is-up is-ltr', upSpeed, null),
								conduitTrack('is-down is-ltr', downSpeed, null)
							]),
							E('div', { class: 'tyf-fe-mod is-pe ' + feStateCls }, [
								E('div', { class: 'tyf-fe-mod-top' }, [
									E('span', { class: 'tyf-fe-mod-name' }, 'PE 报文编辑'),
									E('span', { class: 'tyf-fe-mod-tag' }, '改写')
								]),
								E('div', { class: 'tyf-fe-mod-sub' }, 'NAT / PPPoE / VLAN'),
								E('div', { class: 'tyf-fe-cap-bar' }, [
									E('span', { class: 'tyf-fe-cap-fill ' + feStateCls, style: 'width:' + slotPct.toFixed(1) + '%' })
								]),
								E('div', { class: 'tyf-fe-mod-meta' }, '校验和 · ' + slotInfo)
							]),
							E('div', { class: 'tyf-fe-dual-link' }, [
								conduitTrack('is-up is-ltr', upSpeed, null),
								conduitTrack('is-down is-ltr', downSpeed, null)
							]),
							E('div', { class: 'tyf-fe-mod is-qm ' + feStateCls }, [
								E('div', { class: 'tyf-fe-mod-top' }, [
									E('span', { class: 'tyf-fe-mod-name' }, 'QM 队列管理'),
									E('span', { class: 'tyf-fe-mod-tag' }, 'DeepQ')
								]),
								E('div', { class: 'tyf-fe-mod-sub' }, 'VoQ 调度 · EQ0+EQ8'),
								E('div', { class: 'tyf-fe-cap-bar' }, [
									E('span', { class: 'tyf-fe-cap-fill ' + feStateCls, style: 'width:' + qmPct + '%' })
								]),
								E('div', { class: 'tyf-fe-mod-meta' }, '防突发缓冲 · 出队发包')
							])
						]),
						E('div', { class: 'tyf-fe-bus-links' }, [
							E('div', { class: 'tyf-fe-vpair' }, [
								verticalConduit('is-btt', 'is-up', upSpeed),
								verticalConduit('is-btt', 'is-down', downSpeed),
								E('span', { class: 'tyf-fe-vlabel' }, 'Demux 送 FE')
							]),
							E('div', { class: 'tyf-fe-vpair' }, [
								verticalConduit('is-ttb', 'is-up', upSpeed),
								verticalConduit('is-ttb', 'is-down', downSpeed),
								E('span', { class: 'tyf-fe-vlabel' }, '出队回 NI 发')
							])
						]),
						E('div', { class: 'tyf-fe-ni-bus ' + feStateCls }, [
							E('span', { class: 'tyf-fe-mod-name' }, 'NI 网络接口层'),
							E('span', { class: 'tyf-fe-ni-desc' }, 'MAC · DMA · L3FE Demux（承接 LAN 与 PON 收发汇总，并直连 FE / QM / CPU）')
						])
					]),
					E('div', { class: 'tyf-fe-conduit' }, [
						conduitTrack('is-up is-ltr', upSpeed, 'PON →'),
						conduitTrack('is-down is-rtl', downSpeed, downLabel)
					]),
					E('div', { class: 'tyf-fe-node tyf-fe-endpoint ' + (ponUp ? 'is-up' : '') }, [
						E('div', { class: 'tyf-fe-node-head' }, [E('i', { class: 'tyf-fe-ndot' }), 'PON 光口']),
						E('div', { class: 'tyf-fe-node-val' }, ponProto),
						E('div', { class: 'tyf-fe-node-sub' }, ponAttach + ' · PDC/PUC')
					])
				])
			])
		]),
		E('div', { class: 'tyf-fe-legend' }, [
			E('span', { class: 'tyf-fe-leg-item' }, [E('i', { class: 'tyf-fe-swatch is-up' }), '上行直通：LAN → NI → FE → PE → QM → NI → PON']),
			E('span', { class: 'tyf-fe-leg-item' }, [E('i', { class: 'tyf-fe-swatch is-down' }), '下行直通：PON → NI → FE → PE → QM(DeepQ) → NI → LAN']),
			E('span', { class: 'tyf-fe-leg-item' }, [E('i', { class: 'tyf-fe-swatch is-cpu' }), 'CPU 慢路径 & 建流下发'])
		])
	]);
}

function offloadFlowsTable(fp) {
	var list = (fp && fp.entries) || [];
	var total = (fp && fp.total_entries != null) ? fp.total_entries : list.length;
	var title = list.length
		? ('查看硬件流表详情（' + (total > list.length ? ('前 ' + list.length + ' / 共 ' + total) : ('共 ' + list.length)) + ' 条）')
		: '查看硬件流表详情（暂无活跃流）';

	return E('details', { class: 'tyf-fe-details', 'data-tyf-fold': 'fe-flows' }, [
		E('summary', {}, title),
		list.length ? E('div', { class: 'tyf-fe-table-wrap' }, [
			E('table', { class: 'tyf-fe-table' }, [
				E('thead', {}, E('tr', {}, [
					E('th', {}, '类型'),
					E('th', {}, '通道方向'),
					E('th', {}, 'Hash 槽'),
					E('th', {}, '计数槽'),
					E('th', {}, '命中包数'),
					E('th', {}, '命中字节')
				])),
				E('tbody', {}, list.map(function(row) {
					var kind = row.k === 'bridge' || row.l ? '二层桥接' : String(row.k || '').toUpperCase();
					var activeStat = row.p > 0 || row.b > 0;
					return E('tr', {}, [
						E('td', {}, kind || '—'),
						E('td', {}, value(row.in) + ' → ' + value(row.out)),
						E('td', {}, value(row.h)),
						E('td', {}, activeStat ? ('#' + value(row.c)) : '活动跟踪'),
						E('td', {}, activeStat ? String(row.p) : '—'),
						E('td', {}, activeStat ? formatBytes(row.b) : '—')
					]);
				}))
			]),
			E('p', { class: 'tyf-note' }, '硬件最多为 32 个接口/流组合分配独立精确计数器；其余显示“活动跟踪”的流同样由 FE 芯片全速硬件转发。如需查看明文 IP/端口五元组（含 [HW_OFFLOAD] 标记），可前往“状态 → 实时信息 → 连接”。')
		]) : E('p', { class: 'tyf-note' }, '当前 FE 硬件流表为空，或调试接口未返回流表条目。')
	]);
}

function offloadState(software, hardware, fe) {
	var available = flag(fe.available), enabled = flag(fe.enabled);
	var bindings = fe.bindings == null ? null : Number(fe.bindings);

	if (!software)
		return ['未启用', 'muted', '防火墙未开启流量卸载，所有转发均经由 CPU 处理'];
	if (!hardware)
		return ['仅软件卸载', 'muted', '硬件卸载未开启，流量经由 CPU 软件 Flowtable 转发'];
	if (fe.error != null && Number(fe.error) !== 0)
		return ['运行异常', 'danger', '错误码：' + fe.error];
	if (!available)
		return ['硬件不可用', 'danger', '已请求硬件卸载，但驱动未提供 FE'];
	if (!enabled)
		return ['硬件未就绪', 'danger', '已请求硬件卸载，但 FE 引擎未启用'];
	if (!bindings)
		return ['已启用', 'good', 'FE 引擎已就绪，尚无接口完成卸载绑定'];
	return ['已启用', 'good', null];
}

function offloadCard(data, software, hardware) {
	var fe = data.fe || {};
	var fp = data.fe_paths || null;
	var bindings = fe.bindings == null ? null : Number(fe.bindings);
	var state = offloadState(software, hardware, fe);
	var rates = sampleRates(data);

	var txRateStr = formatRate(rates.ponTxBps);
	var rxRateStr = formatRate(rates.ponRxBps);
	var upText = fp && fp.upstream
		? (fp.upstream.flows + ' 条' + (txRateStr ? ' · ' + txRateStr : '') + (fp.upstream.bytes > 0 ? '（计数槽 ' + formatBytes(fp.upstream.bytes) + '）' : ''))
		: (txRateStr ? txRateStr : '采样中…');
	var downText = fp && fp.downstream
		? (fp.downstream.flows + ' 条' + (rxRateStr ? ' · ' + rxRateStr : '') + (fp.downstream.bytes > 0 ? '（计数槽 ' + formatBytes(fp.downstream.bytes) + '）' : ''))
		: (rxRateStr ? rxRateStr : '采样中…');

	var protoDetail = fp && fp.upstream && fp.downstream
		? ('IPv4 ' + (fp.upstream.ipv4 + fp.downstream.ipv4) + ' · IPv6 ' + (fp.upstream.ipv6 + fp.downstream.ipv6))
		: null;
	var slotDetail = fe.counted_flows != null && fe.counter_slots != null
		? ('计数槽 ' + fe.counted_flows + '/' + fe.counter_slots) : null;
	var flowDetail = [
		value(fe.flows) + ' / ' + value(fe.hash_entries || 65536),
		bindings == null ? null : ('绑定 ' + bindings + ' 口'),
		protoDetail,
		slotDetail,
		Number(fe.bridge_flows || 0) > 0 ? ('桥接 ' + fe.bridge_flows) : null
	].filter(Boolean).join(' · ');

	return card('硬件转发', badge(state[0], state[1]), E('div', {}, [
		offloadDiagram(data, software, hardware, fe, rates),
		rows([
			['卸载模式', (software ? '软件开' : '软件关') + ' / ' + (hardware ? '硬件开' : '硬件关') + ' · FE ' + (flag(fe.available) ? flag(fe.enabled) ? '已启用' : '未启用' : '不可用')],
			['活跃硬件流', flowDetail],
			['上行 / 下行通道', '↑ ' + upText + '  |  ↓ ' + downText]
		]),
		state[2] ? E('p', { class: 'tyf-note' }, state[2]) : null,
		offloadFlowsTable(fp)
	]));
}

return baseclass.extend({
	modes: modes, value: value, badge: badge, rows: rows, card: card,
	temperature: temperature, voltage: voltage, power: power, opticalRows: opticalRows, bosaName: bosaName,
	omciLive: omciLive, ponState: ponState, ponCard: ponCard, offloadCard: offloadCard,
	style: function() { return E('link', { rel: 'stylesheet', href: L.resource('rtl9617c/status.css') }); },
	callStatus: callStatus
});
