#!/usr/bin/env bash
set -euo pipefail
umask 077

script_dir=$(cd -- "$(dirname -- "$0")" && pwd -P)
state_file=${HOPX_DEPLOY_STATE:-${XDG_CONFIG_HOME:-$HOME/.config}/hopx/deployment-path}
default_dir=${HOPX_INSTALL_PATH:-/opt/hopx}
source_archive=https://codeload.github.com/hiapb/hopx/tar.gz/refs/heads/main

say() { printf '%s\n' "$*"; }
die() { say "$*" >&2; exit 1; }
need() { command -v "$1" >/dev/null || die "缺少命令 $1"; }
recorded() { [[ -f $state_file ]] && cat "$state_file" || true; }
instance() { workdir=$(recorded); [[ -n $workdir && -f $workdir/.env ]] || die '未检测到部署'; }
compose() {
  local project
  local -a options=()
  project=$(getenv HOPX_COMPOSE_PROJECT)
  if [[ -n $project ]]; then options=(-p "$project"); fi
  docker compose ${options[@]+"${options[@]}"} --project-directory "$workdir" --env-file "$workdir/.env" -f "$workdir/compose.yaml" "$@"
}
compose_project() {
  printf '%s' "$workdir" | openssl dgst -sha256 | awk '{print "hopx-" substr($NF,1,20)}'
}
secret() { openssl rand -hex "$1"; }
initial_password() {
  local value
  while true; do
    value=$(openssl rand -base64 24) || return
    value=${value//\//_}
    if [[ $value == *[A-Z]* && $value == *[a-z]* && $value == *[0-9]* && $value == *[+_]* ]]; then
      printf '%s\n' "$value"
      return
    fi
  done
}
getenv() { sed -n "s/^$1=//p" "$workdir/.env" | head -n 1; }
hash_file() { openssl dgst -sha256 "$1" | awk '{print $NF}'; }

load_source() {
  local tmp_dir=$1 candidate=$script_dir
  if [[ ! -f $candidate/Dockerfile && -s $script_dir/source-path ]]; then
    IFS= read -r candidate < "$script_dir/source-path"
  fi
  if [[ $candidate == /* && -f $candidate/Dockerfile && -f $candidate/compose.yaml && -f $candidate/install.sh ]]; then
    source=$candidate
    source_checkout=$candidate
    return
  fi
  need curl
  need tar
  say '正在从 GitHub 下载 HopX 源码…'
  curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
    --connect-timeout 15 --max-time 180 --retry 2 --output "$tmp_dir/hopx.tar.gz" "$source_archive" ||
    die '下载 HopX 源码失败，请检查服务器能否访问 codeload.github.com'
  source=$tmp_dir/source
  source_checkout=''
  mkdir -- "$source"
  tar -xzf "$tmp_dir/hopx.tar.gz" -C "$source" --strip-components=1 ||
    die '解压 HopX 源码失败'
  [[ -f $source/Dockerfile && -f $source/compose.yaml && -f $source/install.sh ]] ||
    die '下载的 HopX 源码不完整'
}

save_management_script() {
  install -m 0700 -- "$source/install.sh" "$workdir/manage.sh"
  printf '%s\n' "$source_checkout" > "$workdir/source-path"
}

access() {
  say "访问地址：$(getenv HOPX_PUBLIC_URL)"
  say "数据目录：$workdir/data"
}

image_label() { printf 'hopx:%s' "$1"; }

build_panel() {
  docker build -t "$1" --build-arg "HOPX_VERSION=$2" "$3"
}

release_openssl() {
  local image=$1 directory=$2
  shift 2
  docker run --rm --network none --cap-drop ALL --security-opt no-new-privileges \
    --user "$(id -u):$(id -g)" --mount "type=bind,src=$directory,dst=/signing,readonly" \
    --workdir /signing --entrypoint /usr/bin/openssl "$image" "$@" </dev/null
}

make_release() (
  local image=$1 version=$2 destination=$3 source=${4:-} existing=${5:-}
  local container='' build_dir='' signing_dir arch bin digest signature first=1
  local artifacts="$workdir/releases/$version"
  signing_dir=$(mktemp -d)
  trap 'if [[ -n $container ]]; then docker rm "$container" >/dev/null 2>&1 || true; fi
        if [[ -n $build_dir ]]; then
          rm -f -- "$build_dir/hopx-node-linux-amd64" "$build_dir/hopx-node-linux-arm64" "$build_dir/verify-amd64" "$build_dir/verify-arm64"
          rmdir -- "$build_dir"
        fi
        rm -rf -- "$signing_dir"' EXIT
  mkdir -p "$artifacts"
  chmod 0755 "$workdir/releases" "$artifacts"
  if [[ -n $source ]]; then
    build_dir=$(mktemp -d)
    docker build --target node-artifacts --output "type=local,dest=$build_dir" --build-arg "HOPX_VERSION=$version" "$source"
  fi
  container=$(docker create "$image")
  for arch in amd64 arm64; do
    if [[ -n $build_dir ]]; then
      install -m 0644 "$build_dir/hopx-node-linux-$arch" "$artifacts/node-$arch"
      install -m 0644 "$build_dir/verify-$arch" "$artifacts/verify-$arch"
    elif [[ -n $existing && -f $existing/node-$arch ]]; then
      install -m 0644 "$existing/node-$arch" "$artifacts/node-$arch"
    else
      docker cp "$container:/usr/local/bin/hopx-node-linux-$arch" "$artifacts/node-$arch"
      chmod 0644 "$artifacts/node-$arch"
    fi
  done
  for bin in node-install.sh node-runner.sh; do
    docker cp "$container:/usr/local/share/hopx/$bin" "$workdir/releases/$bin"
    chmod 0644 "$workdir/releases/$bin"
  done
  # Older installed images can still be used to restore an existing backup.
  local -a signer=(release_openssl "$image" "$signing_dir")
  if [[ -z $source ]] && ! "${signer[@]}" version >/dev/null 2>&1; then
    signer=(openssl)
  fi
  if [[ -f $workdir/keys/release.pem ]]; then
    cp -- "$workdir/keys/release.pem" "$signing_dir/release.pem"
  else
    (cd -- "$signing_dir" && "${signer[@]}" genpkey -algorithm ED25519) > "$signing_dir/release.pem" ||
      die '无法生成节点发行签名密钥'
    install -m 0600 -- "$signing_dir/release.pem" "$workdir/keys/release.pem"
  fi
  chmod 0600 "$workdir/keys/release.pem"
  (cd -- "$signing_dir" && "${signer[@]}" pkey -in release.pem -pubout) > "$workdir/releases/release.pem" ||
    die '无法导出节点发行签名公钥'
  chmod 0644 "$workdir/releases/release.pem"
  {
    printf '{'
    for arch in amd64 arm64; do
      digest=$(hash_file "$artifacts/node-$arch")
      printf '%s\nlinux-%s\n%s\n' "$version" "$arch" "$digest" > "$signing_dir/message"
      signature=$(cd -- "$signing_dir" && "${signer[@]}" pkeyutl -sign -inkey release.pem -rawin -in message | openssl base64 -A) ||
        die '无法签署节点发行包'
      printf '%s\n%s\n%s\n%s\n' "$version" "/releases/$version/node-$arch" "$digest" "$signature" > "$artifacts/install-$arch.txt"
      chmod 0644 "$artifacts/install-$arch.txt"
      (( first == 1 )) || printf ','
      first=0
      printf '"linux-%s":{"version":"%s","url":"/releases/%s/node-%s","sha256":"%s","signature":"%s"}' \
        "$arch" "$version" "$version" "$arch" "$digest" "$signature"
    done
    printf '}\n'
  } > "$destination"
  chmod 0644 "$destination"
)
publish_bootstrap() {
  local version=$1
  for arch in amd64 arm64; do
    cp -- "$workdir/releases/$version/install-$arch.txt" "$workdir/releases/.install-$arch.next"
    chmod 0644 "$workdir/releases/.install-$arch.next"
    mv -- "$workdir/releases/.install-$arch.next" "$workdir/releases/install-$arch.txt"
  done
}

get_version() {
  local version=${HOPX_VERSION:-$(date -u +%Y%m%d.%H%M%S)}
  [[ $version =~ ^[A-Za-z0-9._-]{1,64}$ ]] || die '发行版本格式无效'
  printf '%s\n' "$version"
}

import_initial_database() (
  local image=$1 source_db=$2 converted
  [[ -f $source_db ]] || die '找不到 nyanpass SQLite 备份'
  source_db=$(cd -- "$(dirname -- "$source_db")" && pwd -P)/$(basename -- "$source_db")
  [[ ! -s $source_db-wal ]] || die '备份仍有 WAL，请用 SQLite .backup 生成独立快照'
  [[ ! -e $workdir/data/hopx.db ]] || die '迁移需要空的 HopX 数据目录'
  converted=$(mktemp -d "$workdir/data/.import-XXXXXX")
  trap 'rm -rf -- "$converted"' EXIT
  cp -- "$source_db" "$converted/legacy.db"
  HOPX_MIGRATION_ADMIN_PASSWORD=$pass docker run --rm --network none \
    --user "$(id -u):$(id -g)" -e "HOPX_ADMIN=$name" -e HOPX_MIGRATION_ADMIN_PASSWORD \
    --mount "type=bind,src=$converted,dst=/data" \
    "$image" --legacy-db /data/legacy.db --db /data/hopx.db </dev/null
  mv -- "$converted/hopx.db" "$workdir/data/hopx.db"
)

install_service() (
  for cmd in docker openssl tar; do need "$cmd"; done
  local source source_checkout source_tmp path port public name pass version image bind
  read -r -p "安装路径 [默认: $default_dir]: " path
  path=${path:-$default_dir}
  [[ $path == /* && $path != / ]] || die '请使用有效的绝对路径'
  [[ ! -e $path/.env ]] || die '部署已存在，请使用 2 升级服务'
  read -r -p '对外端口 [默认: 38571]: ' port
  port=${port:-38571}
  [[ $port =~ ^[1-9][0-9]{0,4}$ && $port -le 65535 ]] || die '端口无效'
  say '使用 HTTPS 反代时，请填写浏览器访问的公网地址，例如 https://panel.example.com。'
  read -r -p "面板访问 URL [默认: http://127.0.0.1:$port]: " public
  public=${public:-http://127.0.0.1:$port}
  local url_pattern='^https?://([A-Za-z0-9._-]+|\[[A-Fa-f0-9:]+\])(:[0-9]{1,5})?$'
  [[ $public =~ $url_pattern ]] || die '面板访问 URL 格式无效'
  if command -v lsof >/dev/null && lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
    die "端口 $port 已被占用"
  fi
  read -r -p '管理员账号 [默认: admin]: ' name
  name=${name:-admin}
  [[ $name =~ ^[A-Za-z0-9._@-]{2,64}$ ]] || die '管理员账号格式无效'
  if [[ -n ${HOPX_SETUP_PASSWORD:-} ]]; then
    pass=$HOPX_SETUP_PASSWORD
  else
    read -r -s -p '管理员密码 [直接回车生成]: ' pass
    printf '\n'
    if [[ -z $pass ]]; then
      pass=$(initial_password)
    fi
  fi
  [[ $pass =~ ^[A-Za-z0-9._@!%+-]{10,72}$ ]] || die '密码须为 10–72 位字符，可使用字母、数字和 ._@!%+-'
  source_tmp=$(mktemp -d)
  trap 'rm -rf -- "$source_tmp"' EXIT
  load_source "$source_tmp"
  mkdir -p "$path"
  workdir=$(cd -- "$path" && pwd -P)
  mkdir -p "$workdir"/{data,releases,keys,backups}
  chmod 0700 "$workdir/data" "$workdir/keys" "$workdir/backups"
  [[ -f $workdir/keys/backup.key ]] || secret 64 > "$workdir/keys/backup.key"
  version=$(get_version)
  image=$(image_label "$version")
  build_panel "$image" "$version" "$source"
  if [[ -n ${HOPX_NYANPASS_DB:-} ]]; then
    import_initial_database "$image" "$HOPX_NYANPASS_DB"
  fi
  make_release "$image" "$version" "$workdir/releases/manifest.json" "$source"
  publish_bootstrap "$version"
  cp -- "$source/compose.yaml" "$workdir/compose.yaml"
  save_management_script
  bind=${HOPX_HOST:-127.0.0.1}
  if [[ -z ${HOPX_HOST:-} && $public =~ ^https?://(localhost|127\.0\.0\.1|\[::1\])(:[0-9]+)?$ ]]; then
    bind=127.0.0.1
    if [[ $public == *\[::1\]* ]]; then bind='[::1]'; fi
  fi
  cat > "$workdir/.env" <<ENV
HOPX_IMAGE=$image
HOPX_COMPOSE_PROJECT=$(compose_project)
HOPX_UID=$(id -u)
HOPX_GID=$(id -g)
HOPX_PORT=$port
HOPX_HOST=$bind
HOPX_ADMIN=$name
HOPX_PUBLIC_URL=$public
HOPX_PAYMENT_SECRET=$(secret 32)
ENV
  printf '%s' "$pass" | HOPX_ADMIN="$name" HOPX_PASSWORD= compose run --rm -T --no-deps hopx --init-admin
  mkdir -p "$(dirname -- "$state_file")"
  printf '%s\n' "$workdir" > "$state_file"
  say "管理员账号：$name"
  say "初始密码：$pass"
  unset pass
  HOPX_PASSWORD= compose up -d --wait --wait-timeout 100
  access
)

backup_archive() (
  set -e
  instance
  local tmp stamp key enc mac target
  tmp=$(mktemp -d "$workdir/backups/.prepare-XXXXXX")
  trap 'rm -rf -- "$tmp"' EXIT
  stamp=$(date -u +%Y%m%dT%H%M%SZ)
  key=$(tr -d '\r\n' < "$workdir/keys/backup.key")
  [[ $key =~ ^[0-9a-f]{128}$ ]] || die '备份密钥格式无效'
  enc=${key:0:64}
  mac=${key:64:64}
  if [[ -n $(compose ps --status running -q hopx) ]]; then
    local snapshot="/data/.snapshot-$stamp-$$.db"
    compose exec -T hopx /usr/local/bin/hopx-panel --backup "$snapshot" </dev/null
    mv -- "$workdir$snapshot" "$tmp/hopx.db"
  else
    compose run --rm -T --no-deps hopx --backup "/data/.snapshot-$stamp-$$.db" </dev/null
    mv -- "$workdir/data/.snapshot-$stamp-$$.db" "$tmp/hopx.db"
  fi
  awk '!/^HOPX_PASSWORD=/' "$workdir/.env" > "$tmp/env"
  cp -- "$workdir/keys/release.pem" "$tmp/release.pem"
  tar -C "$tmp" -czf "$tmp/state.tgz" hopx.db env release.pem
  HOPX_ENCRYPTION_KEY=$enc openssl enc -aes-256-cbc -pbkdf2 -iter 250000 -salt -in "$tmp/state.tgz" -out "$tmp/state.enc" -pass env:HOPX_ENCRYPTION_KEY
  target="$workdir/backups/hopx-$stamp-$$.hopx"
  {
    openssl dgst -sha256 -mac HMAC -macopt "hexkey:$mac" "$tmp/state.enc" | awk '{print $NF}'
    cat "$tmp/state.enc"
  } > "$target"
  say "$target"
)

restore_archive() (
  set -e
  local file keypath key enc mac tmp expected actual name response image version deployed source source_checkout target
  local restore_new=false
  deployed=$(recorded)
  workdir=${HOPX_RESTORE_PATH:-$deployed}
  read -r -p '备份文件路径: ' file
  [[ -r $file ]] || die '找不到备份文件'
  if [[ -n $deployed && -r $deployed/keys/backup.key ]]; then
    read -r -p "备份密钥路径 [默认: $deployed/keys/backup.key]: " keypath
    keypath=${keypath:-$deployed/keys/backup.key}
  else
    read -r -p '备份密钥路径: ' keypath
  fi
  [[ -r $keypath ]] || die '找不到备份密钥'
  key=$(tr -d '\r\n' < "$keypath")
  [[ $key =~ ^[0-9a-f]{128}$ ]] || die '备份密钥格式无效'
  enc=${key:0:64}
  mac=${key:64:64}
  tmp=$(mktemp -d)
  trap 'rm -rf -- "$tmp"' EXIT
  IFS= read -r expected < "$file"
  [[ $expected =~ ^[0-9a-f]{64}$ ]] || die '备份格式无效'
  tail -c +66 "$file" > "$tmp/state.enc"
  actual=$(openssl dgst -sha256 -mac HMAC -macopt "hexkey:$mac" "$tmp/state.enc" | awk '{print $NF}')
  [[ $actual == "$expected" ]] || die '备份完整性校验失败'
  HOPX_ENCRYPTION_KEY=$enc openssl enc -d -aes-256-cbc -pbkdf2 -iter 250000 -in "$tmp/state.enc" -out "$tmp/state.tgz" -pass env:HOPX_ENCRYPTION_KEY
  for name in hopx.db env release.pem; do
    tar -xzOf "$tmp/state.tgz" "$name" > "$tmp/$name"
  done
  [[ $(head -c 15 "$tmp/hopx.db") == 'SQLite format 3' ]] || die '备份数据库格式无效'
  if [[ -z $workdir ]]; then
    read -r -p "恢复目标路径 [默认: $default_dir]: " target
    workdir=${target:-$default_dir}
  fi
  [[ $workdir == /* && $workdir != / && ! -L $workdir ]] || die '请指定独立的绝对部署路径'
  if [[ -f $workdir/.env && -f $workdir/compose.yaml && -d $workdir/keys ]]; then
    image=$(getenv HOPX_IMAGE)
  else
    [[ ! -e $workdir ]] || die '目标目录已有数据，请使用新的路径'
    restore_new=true
    load_source "$tmp"
    version=$(get_version)
    image=$(image_label "$version")
    build_panel "$image" "$version" "$source"
  fi
  version=${image#hopx:}
  docker run --rm --network none --user "$(id -u):$(id -g)" \
    --mount "type=bind,src=$tmp,dst=/validate" "$image" --check-db /validate/hopx.db </dev/null
  if [[ $restore_new == true ]]; then
    mkdir -p -- "$(dirname -- "$workdir")"
    mkdir -- "$workdir"
    workdir=$(cd -- "$workdir" && pwd -P)
    mkdir "$workdir"/{data,keys,backups}
    cp -- "$tmp/hopx.db" "$workdir/data/hopx.db"
    cp -- "$tmp/release.pem" "$workdir/keys/release.pem"
    printf '%s\n' "$key" > "$workdir/keys/backup.key"
    awk '!/^HOPX_(UID|GID|IMAGE|PASSWORD|COMPOSE_PROJECT)=/' "$tmp/env" > "$workdir/.env"
    printf 'HOPX_UID=%s\nHOPX_GID=%s\nHOPX_IMAGE=%s\n' "$(id -u)" "$(id -g)" "$image" >> "$workdir/.env"
    printf 'HOPX_COMPOSE_PROJECT=%s\n' "$(compose_project)" >> "$workdir/.env"
    if [[ -n ${HOPX_RESTORE_PORT:-} ]]; then
      [[ $HOPX_RESTORE_PORT =~ ^[1-9][0-9]{0,4}$ && $HOPX_RESTORE_PORT -le 65535 ]] || die '恢复端口无效'
      awk -v port="$HOPX_RESTORE_PORT" '/^HOPX_PORT=/{print "HOPX_PORT=" port;next}1' "$workdir/.env" > "$tmp/new-env"
      mv -- "$tmp/new-env" "$workdir/.env"
    fi
    if [[ -n ${HOPX_RESTORE_URL:-} ]]; then
      [[ $HOPX_RESTORE_URL =~ ^https?://([A-Za-z0-9._-]+|\[[A-Fa-f0-9:]+\])(:[0-9]{1,5})?$ ]] || die '恢复 URL 无效'
      awk -v url="$HOPX_RESTORE_URL" '/^HOPX_PUBLIC_URL=/{print "HOPX_PUBLIC_URL=" url;next}1' "$workdir/.env" > "$tmp/new-env"
      mv -- "$tmp/new-env" "$workdir/.env"
    fi
    cp -- "$source/compose.yaml" "$workdir/compose.yaml"
    save_management_script
    make_release "$image" "$version" "$workdir/releases/manifest.json" "$source"
    publish_bootstrap "$version"
    if ! compose up -d --wait --wait-timeout 100 </dev/null; then
      compose down </dev/null || true
      die "恢复后的服务未通过就绪检查，数据保存在 $workdir"
    fi
    mkdir -p "$(dirname -- "$state_file")"
    printf '%s\n' "$workdir" > "$state_file"
    say '数据已恢复到新部署。'
    access
    return
  fi
  read -r -p '恢复将替换当前部署的数据并保留恢复前备份。是否继续？(y/N): ' response
  [[ $response =~ ^[Yy]$ ]] || return 0
  local existing_artifacts="$workdir/releases/$version"
  (
    workdir="$tmp/release"
    mkdir -p "$workdir/keys"
    cp -- "$tmp/release.pem" "$workdir/keys/release.pem"
    make_release "$image" "$version" "$workdir/releases/manifest.json" "" "$existing_artifacts"
    publish_bootstrap "$version"
  )
  backup_archive
  local saved="$workdir/backups/pre-restore-$(date -u +%Y%m%dT%H%M%SZ)-$$"
  mkdir "$saved"
  compose stop
  mv -- "$workdir/data" "$saved/data"
  awk '!/^HOPX_PASSWORD=/' "$workdir/.env" > "$saved/env"
  cp -- "$workdir/keys/release.pem" "$saved/release.pem"
  mkdir "$workdir/data"
  cp -- "$tmp/hopx.db" "$workdir/data/hopx.db"
  cp -- "$tmp/release.pem" "$workdir/keys/release.pem"
  if ! compose up -d --wait --wait-timeout 100; then
    compose stop
    mv -- "$workdir/data" "$saved/failed-data"
    mv -- "$saved/data" "$workdir/data"
    cp -- "$saved/release.pem" "$workdir/keys/release.pem"
    compose up -d --wait --wait-timeout 100
    die "恢复失败，已回到恢复前数据。$saved"
  fi
  for name in release.pem install-amd64.txt install-arm64.txt manifest.json; do
    cp -- "$tmp/release/releases/$name" "$workdir/releases/.$name.next"
    chmod 0644 "$workdir/releases/.$name.next"
    mv -- "$workdir/releases/.$name.next" "$workdir/releases/$name"
  done
  say "数据已恢复。恢复前目录：$saved"
  mkdir -p "$(dirname -- "$state_file")"
  printf '%s\n' "$workdir" > "$state_file"
)

upgrade_service() (
  instance
  local source source_checkout source_tmp version image previous staged
  version=$(get_version)
  image=$(image_label "$version")
  previous=$(getenv HOPX_IMAGE)
  [[ $image != "$previous" ]] || die '当前发行版已安装'
  source_tmp=$(mktemp -d)
  trap 'rm -rf -- "$source_tmp"' EXIT
  load_source "$source_tmp"
  backup_archive
  build_panel "$image" "$version" "$source"
  staged="$workdir/releases/.manifest.next"
  make_release "$image" "$version" "$staged" "$source"
  cp -- "$workdir/.env" "$workdir/.env.previous"
  awk -v image="$image" '/^HOPX_IMAGE=/{print "HOPX_IMAGE=" image;next}!/^HOPX_PASSWORD=/' "$workdir/.env.previous" > "$workdir/.env"
  if ! HOPX_PASSWORD= compose up -d --wait --wait-timeout 100; then
    mv -- "$workdir/.env.previous" "$workdir/.env"
    compose up -d --wait --wait-timeout 100
    die '新版未通过就绪检查，已恢复上一版本镜像'
  fi
  rm -f -- "$workdir/.env.previous"
  mv -- "$staged" "$workdir/releases/manifest.json"
  publish_bootstrap "$version"
  save_management_script
  say '面板升级成功，节点将自动按批更新。'
  access
)

migrate_nyanpass() (
  instance
  need docker
  need openssl
  local option source answer tmp sql_network='' sql_container='' report ready attempt image uid gid
  local HOPX_NY_ADDRESS HOPX_NY_DATABASE HOPX_NY_USER HOPX_NY_PASSWORD HOPX_NY_TLS HOPX_ADMIN
  say '1) 连接在线 MySQL / MariaDB'
  say '2) 从 .sql.gz 下载链接导入'
  say '0) 返回'
  read -r -p '请选择 [0-2]: ' option
  [[ $option != 0 ]] || return 0
  HOPX_ADMIN=$(getenv HOPX_ADMIN)
  HOPX_ADMIN=${HOPX_ADMIN:-admin}
  HOPX_NY_TLS=true
  case "$option" in
    1)
      read -r -p '数据库地址（主机或主机:端口，默认端口 3306）: ' HOPX_NY_ADDRESS
      read -r -p '数据库名: ' HOPX_NY_DATABASE
      read -r -p '只读用户名: ' HOPX_NY_USER
      read -r -s -p '数据库密码: ' HOPX_NY_PASSWORD
      printf '\n'
      read -r -p '验证数据库 TLS？[Y/n]: ' answer
      if [[ $answer =~ ^[Nn]$ ]]; then HOPX_NY_TLS=false; fi
      [[ -n $HOPX_NY_ADDRESS && -n $HOPX_NY_DATABASE && -n $HOPX_NY_USER ]] || die '请填写地址、库名和用户名'
      ;;
    2)
      need curl
      need gzip
      read -r -p 'SQL 备份下载链接: ' source
      [[ $source =~ ^https?:// ]] || die '请输入 HTTP 或 HTTPS 下载链接'
      ;;
    *) die '无效选项' ;;
  esac
  tmp=$(mktemp -d "$workdir/backups/.nyanpass-XXXXXX")
  trap 'if [[ -n $sql_container ]]; then docker rm -fv "$sql_container" >/dev/null 2>&1 || true; fi
        if [[ -n $sql_network ]]; then docker network rm "$sql_network" >/dev/null 2>&1 || true; fi
        rm -rf -- "$tmp"' EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM

  if [[ $option == 2 ]]; then
    say '正在下载并检查 SQL 备份。'
    curl --fail --silent --show-error --location --proto '=http,https' --proto-redir '=http,https' \
      --connect-timeout 10 --max-time 600 --output "$tmp/source.sql.gz" -- "$source" || die '下载 SQL 备份失败'
    gzip -t "$tmp/source.sql.gz" || die '下载内容不是有效的 gzip 备份'
    HOPX_NY_ADDRESS=nyanpass-db:3306
    HOPX_NY_DATABASE=nyanpass
    HOPX_NY_USER=nyanpass
    HOPX_NY_PASSWORD=$(secret 24)
    HOPX_NY_TLS=false
    sql_network=$(docker network create --internal "hopx-nyanpass-${tmp##*-}") || die '创建临时迁移网络失败'
    sql_container=$(MARIADB_ROOT_PASSWORD=$(secret 24) MARIADB_PASSWORD=$HOPX_NY_PASSWORD docker run -d \
      --network "$sql_network" --network-alias nyanpass-db \
      -e MARIADB_ROOT_PASSWORD -e MARIADB_PASSWORD -e "MARIADB_DATABASE=$HOPX_NY_DATABASE" -e "MARIADB_USER=$HOPX_NY_USER" \
      mariadb:10.11 --local-infile=0) || die '启动临时 MariaDB 失败'
    ready=false
    for ((attempt=0; attempt<60; attempt++)); do
      if docker exec "$sql_container" healthcheck.sh --connect --innodb_initialized >/dev/null 2>&1; then
        ready=true
        break
      fi
      sleep 2
    done
    [[ $ready == true ]] || die '临时 MariaDB 启动超时'
    say '正在还原 SQL 到临时 MariaDB。'
    if ! gzip -dc "$tmp/source.sql.gz" | MYSQL_PWD=$HOPX_NY_PASSWORD docker exec -i --user mysql -e MYSQL_PWD "$sql_container" \
      mariadb --no-defaults --local-infile=0 --binary-mode --user "$HOPX_NY_USER" "$HOPX_NY_DATABASE" \
      >"$tmp/restore.log" 2>&1; then
      die '还原 SQL 失败，请检查备份是否为 nyanpass 的 MySQL 或 MariaDB SQL 导出'
    fi
  fi

  say '正在备份当前 HopX。目标实例须仅含初始管理员。'
  backup_archive
  export HOPX_ADMIN HOPX_NY_ADDRESS HOPX_NY_DATABASE HOPX_NY_USER HOPX_NY_PASSWORD HOPX_NY_TLS
  say '正在导入 nyanpass 数据。'
  if [[ $option == 2 ]]; then
    image=$(getenv HOPX_IMAGE)
    uid=$(getenv HOPX_UID)
    gid=$(getenv HOPX_GID)
    docker run --rm --network "$sql_network" --user "${uid:-65532}:${gid:-65532}" \
      --mount "type=bind,src=$workdir/data,dst=/data" \
      -e HOPX_ADMIN -e HOPX_NY_ADDRESS -e HOPX_NY_DATABASE -e HOPX_NY_USER -e HOPX_NY_PASSWORD -e HOPX_NY_TLS \
      "$image" --migrate-nyanpass >"$tmp/report.json" </dev/null
  else
    compose run --rm -T --no-deps \
      -e HOPX_NY_ADDRESS -e HOPX_NY_DATABASE -e HOPX_NY_USER -e HOPX_NY_PASSWORD -e HOPX_NY_TLS \
      hopx --migrate-nyanpass >"$tmp/report.json" </dev/null
  fi
  report="$workdir/backups/nyanpass-$(date -u +%Y%m%dT%H%M%SZ)-${tmp##*-}.json"
  mv -- "$tmp/report.json" "$report"
  say "迁移完成。报告：$report"
  say '请使用 HopX 原管理员账号重新登录。已导入的规则为暂停状态，原节点需要重新接入。'
)

cron_setup() {
  instance
  need crontab
  say '1) 按分钟间隔备份'
  say '2) 每天固定时间备份'
  say '3) 删除定时备份任务'
  local menu value cron='' tmp mark
  read -r -p '请选择 [1/2/3]: ' menu
  case "$menu" in
    1) read -r -p '分钟间隔 [1,2,3,4,5,6,10,12,15,20,30]: ' value
       [[ $value =~ ^(1|2|3|4|5|6|10|12|15|20|30)$ ]] || die '不支持该时间间隔'
       cron="*/$value * * * *" ;;
    2) read -r -p '每天执行时间 (HH:MM): ' value
       [[ $value =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]] || die '时间格式无效'
       cron="$((10#${value:3:2})) $((10#${value:0:2})) * * *" ;;
    3) ;;
    *) die '无效选项' ;;
  esac
  mark=$(printf '%s' "$state_file" | openssl dgst -sha256 | awk '{print substr($NF,1,16)}')
  tmp=$(mktemp)
  crontab -l 2>/dev/null | awk -v marker="# hopx-$mark" 'index($0, marker)==0' > "$tmp" || true
  if [[ -n $cron ]]; then
    local state_quoted script_quoted log_quoted
    printf -v state_quoted '%q' "$state_file"
    printf -v script_quoted '%q' "$workdir/manage.sh"
    printf -v log_quoted '%q' "$workdir/backups/schedule.log"
    printf '%s HOPX_DEPLOY_STATE=%s /bin/bash %s run-backup >> %s 2>&1 # hopx-%s\n' "$cron" "$state_quoted" "$script_quoted" "$log_quoted" "$mark" >> "$tmp"
  fi
  crontab "$tmp"
  rm -f -- "$tmp"
}

remote_tool() {
  instance
  local kind=$1 action response file remote
  if [[ $kind == ftp ]]; then need curl; else need aws; fi
  say '1) 上传备份'
  say '2) 下载备份'
  say '0) 返回'
  read -r -p '请选择 [0-2]: ' action
  [[ $action == 0 ]] && return 0
  [[ $action == 1 || $action == 2 ]] || die '无效选项'
  read -r -p '远程备份完整地址: ' remote
  if [[ $kind == ftp ]]; then [[ $remote =~ ^(ftp|ftps|sftp):// ]] || die '请输入 FTP/SFTP 地址'
  else [[ $remote == s3://* ]] || die '请输入 S3 对象地址'; fi
  if [[ $action == 1 ]]; then
    read -r -p '本地备份文件 [回车新建]: ' file
    [[ -n $file ]] || file=$(backup_archive | tail -n 1)
    [[ -r $file ]] || die '找不到备份文件'
    if [[ $kind == ftp ]]; then curl --fail --silent --show-error --netrc-optional --upload-file "$file" "$remote"
    else aws s3 cp "$file" "$remote"; fi
  else
    read -r -p '下载保存路径: ' file
    [[ -n $file && ! -e $file ]] || die '请指定未占用的保存路径'
    if [[ $kind == ftp ]]; then curl --fail --silent --show-error --netrc-optional --output "$file" "$remote"
    else aws s3 cp "$remote" "$file"; fi
  fi
  say '传输完成。'
}

remove_service() {
  instance
  local response
  say "将删除 HopX 实例和部署目录 $workdir"
  read -r -p '确认卸载？(y/N): ' response
  [[ $response =~ ^[Yy]$ ]] || return 0
  compose down
  if command -v crontab >/dev/null && crontab -l >/dev/null 2>&1; then
    local mark tmp
    mark=$(printf '%s' "$state_file" | openssl dgst -sha256 | awk '{print substr($NF,1,16)}')
    tmp=$(mktemp)
    crontab -l | awk -v marker="# hopx-$mark" 'index($0, marker)==0' > "$tmp"
    crontab "$tmp"
    rm -f -- "$tmp"
  fi
  [[ $workdir == /* && $workdir != / && -f $workdir/compose.yaml ]] || die '无法验证部署路径'
  rm -rf -- "$workdir"
  rm -f -- "$state_file"
}

main_menu() {
  [[ ! -t 1 || -z ${TERM:-} ]] || clear || true
  local workdir choice
  workdir=$(recorded)
  cat <<MENU
==================================================
              HopX 管理脚本
==================================================
 当前部署路径: ${workdir:-未部署}
--------------------------------------------------
 1) 一键部署
 2) 升级服务
 3) 停止服务
 4) 重启服务
 5) 手动备份
 6) 恢复备份
 7) 定时备份
 8) 完全卸载
 9) 📁 FTP/SFTP 备份工具
10) 📂 S3 备份工具
11) 从 nyanpass 迁移
 0) 退出
==================================================
MENU
  read -r -p '请选择操作 [0-11]: ' choice || exit
  case "$choice" in
    1) (set -e; install_service) ;;
    2) (set -e; upgrade_service) ;;
    3) (set -e; instance; compose stop) ;;
    4) (set -e; instance; compose up -d --wait --wait-timeout 100) ;;
    5) (set -e; backup_archive) ;;
    6) (set -e; restore_archive) ;;
    7) (set -e; cron_setup) ;;
    8) (set -e; remove_service) ;;
    9) (set -e; remote_tool ftp) ;;
    10) (set -e; remote_tool s3) ;;
    11) (set -e; migrate_nyanpass) ;;
    0) exit 0 ;;
    *) say '无效选项。' ;;
  esac
}

case "${1:-}" in
  install) install_service ;;
  upgrade) upgrade_service ;;
  stop) instance; compose stop ;;
  restart) instance; compose up -d --wait --wait-timeout 100 ;;
  backup|run-backup) backup_archive ;;
  restore) restore_archive ;;
  cron) cron_setup ;;
  uninstall) remove_service ;;
  ftp) remote_tool ftp ;;
  s3) remote_tool s3 ;;
  migrate) migrate_nyanpass ;;
  '') set +e; while true; do main_menu; read -r -p '按回车返回主菜单...' || exit 0; done ;;
  *) die '可用命令: install | upgrade | stop | restart | backup | restore | cron | uninstall | run-backup | ftp | s3 | migrate' ;;
esac
