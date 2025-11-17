const request = require('supertest');
const express = require('express'); // Потрібно для імітації запуску сервера
const fs = require('fs');
const path = require('path');
// Важливо: для реальних інтеграційних тестів, вам потрібно запустити ваш 'server.js'
// Для простоти, тут ми імітуємо його:
const app = require('./server'); // Припускаємо, що server.js експортує 'app'

// Налаштування Jest: використовувати свіжу базу даних для тестів
beforeAll(() => {
  // Тут повинна бути логіка для очищення/ініціалізації тестової бази
  // Для SQLite це зазвичай видалення існуючого файлу БД та запуск міграції
  // Оскільки 'npm run pretest' запускає міграцію, ми можемо це пропустити
});

describe('Droids API Integration Tests', () => {

    let newDroidId;
    
    // Тест 1: POST успішне створення (Happy Path)
    it('should create a new droid and return 201', async () => {
        const response = await request(app)
            .post('/droids')
            .send({
                name: 'R2-D2 Lite',
                manufacturer: 'Astromech Corp',
                year_production: 2024,
                status: 'Active',
                model: 'A-2',
                battery_level: 99,
                mission: 'Mapping the system',
                last_maintenance: '2025-11-01'
            });

        expect(response.statusCode).toBe(201);
        expect(response.body.name).toBe('R2-D2 Lite');
        expect(response.body.id).toBeDefined();
        newDroidId = response.body.id; // Зберігаємо ID для подальших тестів
    });
    
    // Тест 2: POST з неправильним payload (400 Bad Request)
    it('should return 400 for invalid data (name too short, battery out of range)', async () => {
        const response = await request(app)
            .post('/droids')
            .send({
                name: 'R', // too short
                battery_level: 101 // out of range
            });

        expect(response.statusCode).toBe(400);
        expect(response.body.error).toBe('Bad Request');
        expect(response.body.fieldErrors).toEqual(expect.arrayContaining([
            expect.objectContaining({ field: 'name', code: 'OUT_OF_RANGE' }),
            expect.objectContaining({ field: 'battery_level', code: 'OUT_OF_RANGE' })
        ]));
    });

    // Тест 3: GET неіснуючого ресурсу (404 Not Found)
    it('should return 404 for a non-existent droid ID', async () => {
        const nonExistentId = 99999;
        const response = await request(app).get(`/droids/${nonExistentId}`);
        
        expect(response.statusCode).toBe(404);
        expect(response.body).toEqual({ error: 'Not found' });
    });

    // Тест 4: DELETE неіснуючого ресурсу (404 Not Found)
    it('should return 404 when attempting to delete a non-existent droid', async () => {
        const nonExistentId = 99999;
        const response = await request(app).delete(`/droids/${nonExistentId}`);
        
        expect(response.statusCode).toBe(404);
        expect(response.body).toEqual({ error: 'Not found' });
    });
    
    // Тест 5: Перевірка health check (Smoketest)
    it('should return 200 for health check endpoint', async () => {
        const response = await request(app).get('/health');
        expect(response.statusCode).toBe(200);
        expect(response.body.status).toBe('UP');
    });

    // Тест 6: PUT з неправильними даними (400 Bad Request)
    it('should return 400 for invalid PUT data', async () => {
        const response = await request(app)
            .put(`/droids/${newDroidId}`)
            .send({
                year_production: 1000 // Too early
            });
        
        expect(response.statusCode).toBe(400);
        expect(response.body.fieldErrors).toEqual(expect.arrayContaining([
            expect.objectContaining({ field: 'year_production' })
        ]));
    });

    // Тест 7: PUT успішне оновлення
    it('should successfully update a droid and return 200', async () => {
        const response = await request(app)
            .put(`/droids/${newDroidId}`)
            .send({
                status: 'Idle',
                battery_level: 80
            });
        
        expect(response.statusCode).toBe(200);
        expect(response.body.status).toBe('Idle');
        expect(response.body.battery_level).toBe(80);
    });
    
    // Тест 8: DELETE успішне видалення
    it('should delete the created droid and return 204', async () => {
        const response = await request(app).delete(`/droids/${newDroidId}`);
        expect(response.statusCode).toBe(204);
    });

    // Примітка: вимога 409 Conflict (дублікат) потребує додаткової логіки в server.js 
    // для перевірки унікальності (наприклад, по полю 'name') та повернення 409. 
    // Наразі SQLite з EXPRESS цього не робить автоматично без додаткових умов UNIQUE.
});