# TG VPN Failover

Независимый системный слой исходящего доступа к Telegram для серверов, где прямое соединение недоступно.

Сервисы-потребители ничего не знают об AdGuard или VLESS. Они используют одну постоянную точку входа:

```text
socks5h://127.0.0.1:1079
```

Схема:

```text
mtg / Telegram bot / другой сервис
              |
              v
       SOCKS5 127.0.0.1:1079
              |
       mtproxy-egress (sing-box)
          /               \
 AdGuard :1080       VLESS auto :1081
                         |
             URLTest по всем Auto+
             fallback на группу Auto
```

## Поведение

- Начальный и предпочтительный маршрут — AdGuard.
- Telegram проверяется через активный upstream каждые 30 секунд.
- После трёх последовательных ошибок маршрут меняется `AdGuard -> VLESS` или `VLESS -> AdGuard`.
- VLESS использует все записи `Авто+` из первой подписки и выбирает доступную через `urltest`. Если `Авто+` отсутствует, используется группа `Авто`.
- Первая непустая строка `/etc/mtproxy-failover/subscriptions` — основной URL подписки. Остальные строки не используются автоматически.
- Подписка обновляется каждые 6 часов; новая конфигурация применяется только после `sing-box check`.

## Состав репозитория

- `scripts/mtproxy-vless-update` — загрузка и преобразование подписки;
- `scripts/mtproxy-failover` — health-check и зеркальное переключение;
- `scripts/tg-vpn-failover-status` — компактное состояние для CLI или управляющего бота;
- `systemd/` — службы и таймеры;
- `config/mtproxy-egress.json` — начальный маршрут через AdGuard;
- `config/egg-cam-control-proxy.conf` — пример настройки потребителя;
- `config/mtg-egress.conf` — необязательное упорядочивание запуска `mtg`.

Секреты и URL подписок в репозиторий не добавляются.

## Подключение потребителя

Для приложения, поддерживающего стандартные proxy-переменные:

```ini
[Service]
Environment=ALL_PROXY=socks5h://127.0.0.1:1079
Environment=all_proxy=socks5h://127.0.0.1:1079
```

Для `mtg`:

```toml
[network]
proxies = ["socks5://127.0.0.1:1079"]
```

Потребитель не должен зависеть от `egg-cam-adguard.service` или управлять переключением самостоятельно. Если общая точка временно недоступна, приложение должно повторять сетевой запрос.

## Проверка

```bash
curl -4 --fail --silent --show-error \
  --proxy socks5h://127.0.0.1:1079 \
  --max-time 20 https://core.telegram.org/getProxyConfig

systemctl is-active mtproxy-egress.service mtproxy-vless.service
systemctl is-active mtproxy-failover.timer mtproxy-vless-update.timer
sudo cat /run/mtproxy-failover/state
sudo cat /run/mtproxy-failover/failures
sudo journalctl -t mtproxy-failover -n 50 --no-pager
/usr/local/sbin/tg-vpn-failover-status
```

Контролируемое ручное переключение для проверки или обслуживания:

```bash
sudo /usr/local/sbin/mtproxy-failover --force-switch
```

## Развёртывание

На сервере должны быть установлены `sing-box`, `curl`, `python3` и `flock`. Файл подписок создаётся отдельно с правами `0600 root:root`, после чего выполняется `sudo ./install.sh`.
