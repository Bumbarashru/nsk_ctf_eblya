# nsk_ctf_eblya

# Базища
```bash
git clone <url>
git pull
git branch                   # смотрим где мы
git checkout -b <nick>       # создаем свою ветку и входим
git push -u origin <nick>    # пушим её в origin
```
# Уже хуетенька
```bash
git status
git add <file>
git commit -m "fix: <что сделал>"
git push                     # пушим в свою ветку
```

# Синхронизация с main
```bash
git checkout main
git pull
git checkout <nick>
git merge main               # залили изменения из main к себе
# если конфликты: фиксим, git add ., git commit
git push
```

# Переключение между ветками
```bash
git checkout <nick_kollegi>  # читаем код коллеги
git checkout <nick>          # вернулись к себе
git stash                    # быстро спрятать грязные изменения при переключении
git stash pop                # вернуть их обратно
                   
# ⚡️ Если всё пошло по пизде
```bash
git log --oneline            # смотрим историю
git reset --hard <commit>    # откат к коммиту (локально)
git push --force             # перезапись своей ветки (аккуратно)
git checkout -- <file>       # откат одного файла
```
