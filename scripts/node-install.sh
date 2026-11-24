#!/usr/bin/env bash
set -euo pipefail
umask 077

green='' yellow='' red='' reset=''
if [[ -t 1 && ${TERM:-dumb} != dumb && -z ${NO_COLOR:-} ]]; then
  green=$'\e[32m' yellow=$'\e[33m' red=$'\e[31m' reset=$'\e[0m'
fi
heading() { printf '\nHopX · %s\n────────────────────────────────\n' "$1"; }
ok() { printf '  %s✓%s  %-12s %s\n' "$green" "$reset" "$1" "${2:-}"; }
notice() { printf '  %s·%s  %s\n' "$yellow" "$reset" "$*"; }
die() { printf '  %s×%s  %s\n' "$red" "$reset" "$*" >&2; exit 1; }

instance_paths() {
  service=hopx-node
  account=hopx-node
  if [[ $instance != default ]]; then
    service="hopx-node-$instance"
    account="hx-node-$instance"
  fi
  dir="/opt/$service"
  config="/etc/$service"
  runner="/usr/local/lib/$service/runner"
  unit="/etc/systemd/system/$service.service"
}

lock_instance() {
  install -d -m 0700 /run/hopx-node
  exec 9>"/run/hopx-node/$service.lock"
  flock -n 9 || die '该节点实例正在安装或卸载，请稍后再试。'
}

require_systemd() {
  [[ $EUID -eq 0 ]] || die '请使用 sudo 执行。'
  for name in systemctl flock; do
    command -v "$name" >/dev/null || die "系统缺少 $name。"
  done
}

manage() {
  local operation=$1 file name response group state choice instance_name
  shift
  instance=''
  if (( $# > 0 )); then
    [[ $operation == uninstall && $# == 2 && $1 == --instance && $2 =~ ^[a-z][a-z0-9-]{0,19}$ ]] ||
      die '用法：hopx-node-manage uninstall [--instance 实例名]'
    instance=$2
  fi
  require_systemd
  heading '本机节点'
  local -a installed=()
  for file in /etc/systemd/system/hopx-node{,-*}.service; do
    [[ -f $file ]] || continue
    name=${file##*/}
    instance_name=${name%.service}
    instance_name=${instance_name#hopx-node}
    instance_name=${instance_name#-}
    instance_name=${instance_name:-default}
    [[ $instance_name =~ ^[a-z][a-z0-9-]{0,19}$ ]] || continue
    if systemctl is-active --quiet "$name"; then state='运行中'; else state='已停止'; fi
    group='设备组未记录'
    if [[ -s /etc/${name%.service}/group ]]; then
      IFS= read -r group < "/etc/${name%.service}/group" || true
    fi
    installed+=("$instance_name")
    printf '  %d) %-20s %s · %s\n' "${#installed[@]}" "$instance_name" "$state" "$group"
  done
  if (( ${#installed[@]} == 0 )); then
    notice '本机没有已安装的 HopX 节点。'
    return
  fi
  [[ $operation == uninstall ]] || return 0
  if [[ -z $instance ]]; then
    read -r -p '  选择要卸载的实例编号（0 取消）：' choice || return 0
    [[ $choice =~ ^[0-9]{1,5}$ ]] || die '请输入列表中的编号。'
    (( 10#$choice != 0 )) || return 0
    (( 10#$choice <= ${#installed[@]} )) || die '请输入列表中的编号。'
    instance=${installed[10#$choice-1]}
  fi
  instance_paths
  [[ -f $unit ]] || die "找不到已安装的实例 $instance。"
  notice "将停止 $service，并清理 $dir、$config 和该实例的服务文件。"
  read -r -p "  请输入实例名 $instance 确认卸载： " response || return 0
  if [[ $response != "$instance" ]]; then notice '已取消卸载。'; return; fi
  lock_instance
  [[ -f $unit ]] || die "实例 $instance 已卸载。"
  systemctl disable --now "$service.service" >/dev/null 2>&1 || die '停止或禁用服务失败，请检查 systemd。'
  ok '停止服务' "$service.service"
  for file in "$dir" "$config" "${runner%/*}"; do
    [[ ! -e $file && ! -L $file ]] || find "$file" -xdev -depth -delete
  done
  rm -f -- "$unit"
  systemctl daemon-reload
  ok '卸载完成' "$instance"
  notice '可在面板的设备组中移除对应节点记录。'
}

case "${1:-}" in
  list|uninstall) manage "$@"; exit ;;
  --help|-h) heading '节点管理'; printf '  list                          查看本机实例\n  uninstall [--instance 名称]  卸载节点实例\n  PANEL_URL TOKEN [安装选项]    接入节点\n'; exit ;;
esac

panel=${1:-}
token=${2:-}
if [[ $# -lt 2 || ! $panel =~ ^https?://[^[:space:]]+$ || -z $token ]]; then
  printf '%s\n' '用法: node-install.sh PANEL_URL TOKEN [--instance NAME] [--name NAME] [--bind IP] [--relay-address HOST:PORT | --prompt-relay-address] [--relay-listen :PORT] [--relay-transport tls|tls-mux|ws|wss|wss-mux|http|https]' >&2
  exit 2
fi
shift 2
require_systemd
case "$(uname -m)" in
  x86_64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) printf '%s\n' '当前架构不受支持' >&2; exit 1 ;;
esac
for name in curl openssl; do
  command -v "$name" >/dev/null || { printf '缺少 %s\n' "$name" >&2; exit 1; }
done
base=${panel%/}
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
write_environment() {
  local key=$1 value=$2
  [[ $value != *$'\n'* && $value != *$'\r'* ]] || { echo '环境参数不能含换行' >&2; return 1; }
  value=${value//\\/\\\\}
  value=${value//\"/\\\"}
  printf '%s="%s"\n' "$key" "$value"
}

instance=default
group_name=''
node_name=''
relay_address=''
relay_listen=''
prompt_relay_address=false
{
  write_environment HOPX_PANEL "$panel"
  write_environment HOPX_TOKEN "$token"
  while (( $# > 0 )); do
    case "$1" in
      --udp-smart-bind) write_environment HOPX_UDP_SMART_BIND true; shift; continue ;;
      --reverse-only) write_environment HOPX_REVERSE_ONLY true; shift; continue ;;
      --prompt-relay-address) prompt_relay_address=true; shift; continue ;;
    esac
    [[ $# -ge 2 ]] || { echo '节点参数缺少值' >&2; exit 2; }
    case "$1" in
      --instance) instance=$2; shift 2; continue ;;
      --name) node_name=$2; shift 2; continue ;;
      --group-name) group_name=$2; shift 2; continue ;;
      --region) key=HOPX_REGION ;;
      --address) key=HOPX_ADDRESS ;;
      --ipv4) key=HOPX_IPV4 ;;
      --ipv6) key=HOPX_IPV6 ;;
      --bind) key=HOPX_BIND ;;
      --interface) key=HOPX_INTERFACE ;;
      --reverse-address) key=HOPX_REVERSE_ADDRESS ;;
      --reverse-listen) key=HOPX_REVERSE_LISTEN ;;
      --relay-listen) relay_listen=$2; shift 2; continue ;;
      --relay-address) relay_address=$2; shift 2; continue ;;
      --relay-transport) key=HOPX_RELAY_TRANSPORT ;;
      *) printf '未知参数 %s\n' "$1" >&2; exit 2 ;;
    esac
    write_environment "$key" "$2"
    shift 2
  done
  [[ $instance =~ ^[a-z][a-z0-9-]{0,19}$ ]] || { echo '实例名称须以小写字母开头，最多 20 位，可用小写字母、数字和连字符' >&2; exit 2; }
  if [[ $instance != default ]]; then
    node_name=${node_name:-$instance}
  fi
  if [[ -n $node_name ]]; then
    write_environment HOPX_NAME "$node_name"
  fi
} > "$tmp/node.env"

instance_paths
heading "节点接入 · $instance"
ok '系统检查' "Linux $arch · systemd"
lock_instance
group_name=$(printf '%s' "$group_name" | tr -d '[:cntrl:]')
install -d -m 0755 /usr/local/bin
manager=$(mktemp /usr/local/bin/.hopx-node-manage.XXXXXX)
trap 'rm -f -- "$manager"; rm -rf -- "$tmp"' EXIT
install -m 0755 -- "${BASH_SOURCE[0]}" "$manager"
mv -fT -- "$manager" /usr/local/bin/hopx-node-manage
write_environment HOPX_RELEASE_KEY "$config/release.pem" >> "$tmp/node.env"
already_registered=false
if [[ -f $dir/state/identity.json && ! -f $dir/state/revoked ]]; then
  [[ -f $unit ]] || die '实例注册文件仍存在，但服务文件缺失。'
  if [[ -n $group_name && -s $config/group ]]; then
    IFS= read -r existing_group < "$config/group" || true
    [[ $group_name == "$existing_group" ]] || notice "此实例已接入 $existing_group。要安装另一个节点，请使用不同的实例名。"
  fi
  already_registered=true
  ok '检查实例' '已注册 · 版本由面板自动管理'
  systemctl enable --now "$service.service" >/dev/null
fi

install_node() {
  if $prompt_relay_address && [[ -z $relay_address ]]; then
    printf '%s' '请输入本机连接地址（如 exit.example.com:38472 或 [2001:db8::1]:38472）：' >&2
    if ! IFS= read -r relay_address; then
      echo '读取连接地址失败，可通过 --relay-address HOST:PORT 指定。' >&2
      exit 2
    fi
    address_pattern='^(\[[[:alnum:]_.%:-]+\]|[[:alnum:]_.%-]+):([0-9]{1,5})$'
    if [[ ! $relay_address =~ $address_pattern ]] || (( 10#${BASH_REMATCH[2]} < 1 || 10#${BASH_REMATCH[2]} > 65535 )); then
      echo '请输入有效的主机地址和端口（1–65535）。' >&2
      exit 2
    fi
  fi
  if [[ -n $relay_address ]]; then
    write_environment HOPX_RELAY_ADDRESS "$relay_address" >> "$tmp/node.env"
    relay_listen=${relay_listen:-:${relay_address##*:}}
  fi
  if [[ -n $relay_listen ]]; then
    write_environment HOPX_RELAY_LISTEN "$relay_listen" >> "$tmp/node.env"
  fi

  url="$base/releases"
  if [[ -n ${HOPX_INSTALL_MIRROR:-} ]]; then
    [[ $HOPX_INSTALL_MIRROR =~ ^https://[^[:space:]/]+/?$ ]] || { echo '海外安装线路地址无效' >&2; exit 2; }
    url="${HOPX_INSTALL_MIRROR%/}/releases"
  fi
  fetch_release() {
    local path=$1 destination=$2
    if [[ -n ${HOPX_OFFLINE_DIR:-} ]]; then
      cp -- "${HOPX_OFFLINE_DIR%/}/$path" "$destination"
    else
      curl -fsS "$url/$path" -o "$destination"
    fi
  }
  notice '正在获取节点发行包…'
  fetch_release "install-$arch.txt" "$tmp/release" || die '获取发行信息失败，请检查面板、安装线路或离线包。'
  if [[ -n ${HOPX_INSTALL_MIRROR:-} && -z ${HOPX_OFFLINE_DIR:-} ]]; then
    curl -fsS "$base/releases/release.pem" -o "$tmp/release.pem"
  else
    fetch_release release.pem "$tmp/release.pem"
  fi
  mapfile -t release < "$tmp/release"
  if [[ ${#release[@]} -ne 4 ]]; then
    echo '节点发行信息格式无效' >&2
    exit 1
  fi
  version=${release[0]}
  artifact=${release[1]}
  checksum=${release[2]}
  signature=${release[3]}
  if [[ ! $version =~ ^[a-zA-Z0-9._-]{1,64}$ || $artifact != "/releases/$version/node-$arch" || ! $checksum =~ ^[0-9a-f]{64}$ ]]; then
    echo '节点发行信息字段无效' >&2
    exit 1
  fi
  printf '%s\nlinux-%s\n%s\n' "$version" "$arch" "$checksum" > "$tmp/message"
  printf '%s' "$signature" | openssl base64 -d -A > "$tmp/signature"
  if ! openssl pkeyutl -verify -pubin -inkey "$tmp/release.pem" -rawin -in "$tmp/message" -sigfile "$tmp/signature" > "$tmp/verify.log" 2>&1; then
    notice '正在使用 HopX 校验程序验证发行签名…'
    verifier="$version/verify-$arch"
    if [[ -n ${HOPX_OFFLINE_DIR:-} ]]; then
      cp -- "${HOPX_OFFLINE_DIR%/}/$verifier" "$tmp/verify" 2>/dev/null ||
        die "离线包缺少校验程序，请重新下载新版离线包。OpenSSL：$(head -n 1 "$tmp/verify.log")"
    elif [[ $base == https://* ]]; then
      curl --proto '=https' -fsS "$base/releases/$verifier" -o "$tmp/verify" ||
        die "面板未提供校验程序，请升级面板后重试。OpenSSL：$(head -n 1 "$tmp/verify.log")"
    else
      die "当前 OpenSSL 无法验签。请使用 HTTPS 面板地址或新版离线包。OpenSSL：$(head -n 1 "$tmp/verify.log")"
    fi
    chmod 0700 "$tmp/verify"
    "$tmp/verify" "$tmp/release.pem" "$tmp/release" ||
      die '节点发行未通过校验，请检查面板签名公钥与发行包。'
  fi
  fetch_release "${artifact#/releases/}" "$tmp/hopx-node"
  [[ $(sha256sum "$tmp/hopx-node" | cut -d ' ' -f1) == "$checksum" ]] || { echo '节点文件校验失败' >&2; exit 1; }
  fetch_release node-runner.sh "$tmp/node-runner.sh"
  ok '下载校验' "$version · 签名与文件校验通过"

  if [[ -f $unit ]]; then
    systemctl stop "$service.service"
  fi
  if [[ -f $dir/state/revoked ]]; then
    retired=$(mktemp -d "$dir/retired.XXXXXX")
    mv -- "$dir/state" "$retired/state"
  fi
  if ! id "$account" >/dev/null 2>&1; then
    useradd --system --user-group --no-create-home --home-dir "$dir" --shell /usr/sbin/nologin "$account"
  fi
  install -d -m 0755 "${runner%/*}"
  install -d -m 0755 "$config"
  install -d -o "$account" -g "$account" -m 0750 "$dir" "$dir/state"
  install -m 0444 "$tmp/release.pem" "$config/release.pem"
  install -m 0755 "$tmp/node-runner.sh" "$runner"
  install -o "$account" -g "$account" -m 0755 "$tmp/hopx-node" "$dir/hopx-node"
  install -m 0600 "$tmp/node.env" "$config/node.env"
  if [[ -n $group_name ]]; then printf '%s\n' "$group_name" > "$config/group"; fi
  cat > "$unit" <<UNIT
[Unit]
Description=HopX forwarding node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$account
Group=$account
EnvironmentFile=$config/node.env
ExecStart=$runner $dir
Restart=on-failure
RestartSec=3
LimitNOFILE=32768
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=$dir
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable --now "$service.service" >/dev/null
}

if ! $already_registered; then install_node; fi

ok '启动服务' "$service.service"
notice '正在等待面板确认节点心跳…'
registered=false
online=false
status=''
for ((attempt=1; attempt<=25; attempt++)); do
  if [[ -f $dir/state/revoked ]]; then die '节点身份已撤销，请重新执行设备组的接入命令。'; fi
  if ! $registered && [[ -f $dir/state/identity.json ]]; then
    if [[ -f $config/node.env ]]; then sed -i '/^HOPX_TOKEN=/d' "$config/node.env"; fi
    ok '节点注册' "${group_name:-$instance}"
    registered=true
  fi
  if $registered && systemctl is-active --quiet "$service.service" && [[ -f $dir/state/startup.status && -s $dir/state/startup.status ]]; then
    read -r status listeners < "$dir/state/startup.status" || true
    if ! $online; then
      ok '面板心跳' '首次同步成功'
      online=true
    fi
    case "$status" in
      applied)
        ok '转发配置' "已应用 · ${listeners:-0} 个监听"
        notice '本机管理命令  sudo hopx-node-manage list'
        exit ;;
      failed)
        notice '规则配置应用失败，面板节点详情可查看具体端口和原因。'
        break ;;
    esac
  fi
  sleep 1
done
if ! $registered; then
  notice '节点尚未完成注册。'
elif ! $online; then
  notice '节点已注册，暂未确认面板心跳。旧版节点可在面板查看在线状态。'
elif [[ $status != failed ]]; then
  notice '面板已收到心跳，正在等待配置应用。'
fi
notice "查看本机日志  sudo journalctl -u $service.service -n 30 --no-pager"
$registered
