Суть уязвимости acceptTradeVulnerable:
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