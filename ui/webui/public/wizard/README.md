# Account Wizard screenshots

Drop these PNGs here. They are shown in the Add Account Wizard (one per step).
If a file is missing the wizard simply omits the image for that step.

| File                     | Wizard step                      |
| ------------------------ | -------------------------------- |
| `registeraccount.png`    | Step 1 — Register in PlayOnline  |
| `sepassword.png`         | Step 3 — Square Enix Password    |
| `polaccountexample.png`  | Step 5 — POL Member List Slot    |
| `characterslotexample.png` | Step 6 — Ingame Character Slot |

Served at `/wizard/<file>` via the WebView2 virtual host (these live in `public/`,
so they are copied to the build output as-is).
