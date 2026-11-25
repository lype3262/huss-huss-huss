# Huss Huss Huss

A clicker game: every click makes a fighter jab the air and shout HUSS.

Play it: https://lype3262.github.io/huss-huss-huss/

Features: synthesized + recorded HUSS sound with a volume slider, a training crew of 12 tiers,
seven upgrade tiers per crew, "Turn Pro" prestige with championship belts and perks,
username/password accounts with cloud saves, an "online now" leaderboard and a ring chat.

The backend is Supabase. Run `supabase-setup.sql`, `supabase-update-2.sql`, `supabase-update-3.sql` and `supabase-update-4.sql`, in order, in the
SQL Editor. The project URL and public key sit in the "Server (Supabase)" section of `index.html`.

## Moderation (Supabase → SQL Editor)

```sql
select huss_admin_reset('TheirUsername');   -- wipe progress on every device
select huss_admin_ban('TheirUsername');     -- ban account + name, remove score and chat
select huss_admin_unban('TheirUsername');
select huss_admin_ban_guest('id-from-the-scores-table');
```
