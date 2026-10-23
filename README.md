# 7scrown RTP + Admin (Railway)

Flask backend + mobile RTP frontend. Admin panel ဖြင့် ဂိမ်းထည့်/ပြင်/ဖြုတ်၊ RTP % သတ်မှတ်၊ Play URL ပြောင်းနိုင်သည်။

## Local run

```bash
cd 7scrown-rtp
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Browser: http://127.0.0.1:8080

## Railway deploy

1. GitHub repo တစ်ခုသို့ ဤ folder အားလုံး push
2. [Railway](https://railway.app) → **New Project** → **Deploy from GitHub**
3. Root directory = ဤ project folder (လိုအပ်ရင်)
4. Variables (optional):
   - `SECRET_KEY` = random long string (session security)
5. Deploy ပြီး public URL ရမည်

`Procfile` / `railway.toml` ပါပြီးသား — start command အလိုအလျောက်သုံးမည်။

## Default Admin

- Password: **`admin123`**
- Security tab မှ ပြောင်းနိုင်သည်

## API

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/games` | Public games + playUrl + disclaimer |
| POST | `/api/admin/login` | `{ "password": "..." }` |
| POST | `/api/admin/logout` | Logout |
| GET | `/api/admin/me` | Session check |
| GET | `/api/admin/data` | Admin full data |
| PUT | `/api/admin/games` | Save games array |
| POST | `/api/admin/settings` | playUrl / disclaimer |
| POST | `/api/admin/password` | Change password |

Data file: `data/games.json` (volume မချထားရင် redeploy မှာ reset ဖြစ်နိုင် — Railway Volume attach လုပ်ရန် အကြံပြု)
