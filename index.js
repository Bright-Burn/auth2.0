const express = require('express');
const axios = require('axios');
const qs = require('qs'); // Для форматирования данных в формате application/x-www-form-urlencoded
const path = require('path');
const app = express();
const cookieParser = require('cookie-parser');
app.use(cookieParser());


// Параметры для подключения к Keycloak
const keycloakBaseUrl = 'http://localhost:8080'
const realm = 'amazing';
const clientId = 'frontend';
const clientSecret = 'WMzFz0G01LEVWMR3liZHMInR71sw9hcF'; // Если используется конфиденциальный клиент
const redirectUri = 'http://localhost:3000/callback';

// Middleware для проверки аутентификации
function isAuthenticated(req) {
    // Здесь мы предполагаем, что токен будет храниться в куках или заголовках
    const token = req.cookies['access_token'] || req.headers['authorization'];
    return token != null; // Проверяем наличие токена
}
// Функция проверки валидности токена
async function isTokenValid(token) {
    try {
        const tokenIntrospectionUrl = `${keycloakBaseUrl}/realms/${realm}/protocol/openid-connect/token/introspect`;
        const data = {
            token: token,
            client_id: clientId,
            client_secret: clientSecret,
        };
debugger
        const response = await axios.post(tokenIntrospectionUrl, qs.stringify(data), {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
        });

        return response.data.active; // true, если токен валидный, иначе false
    } catch (error) {
        console.error('Error validating token:', error.response ? error.response.data : error.message);
        return false;
    }
}

// Маршрут для главной страницы
app.get('/', async (req, res) => {
    const token = req.cookies['access_token'] || req.headers['authorization'];
    if (token && await isTokenValid(token)) {
        // Если токен валидный, отдаем welcome.html
        res.sendFile(path.join(__dirname, 'public', 'build/index.html'));
    } else {
        // Если токена нет или он не валидный, отдаем index.html с кнопкой Login
        res.sendFile(path.join(__dirname, 'public', 'index.html'));
    }
});
app.use(express.static(path.join(__dirname, 'public/build')));
// Маршрут для редиректа на Keycloak
app.get('/login', (req, res) => {
    const keycloakAuthUrl = `${keycloakBaseUrl}/realms/${realm}/protocol/openid-connect/auth?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=openid`;

    res.redirect(keycloakAuthUrl);
});

// Маршрут для обработки callback от Keycloak
app.get('/callback', async (req, res) => {
    const authorizationCode = req.query.code;

    if (!authorizationCode) {
        return res.status(400).send('Authorization code not provided');
    }

    try {
        // Формируем данные для POST-запроса на получение токена
        const tokenUrl = `${keycloakBaseUrl}/realms/${realm}/protocol/openid-connect/token`;

        const data = {
            grant_type: 'authorization_code',
            client_id: clientId,
            client_secret: clientSecret,
            code: authorizationCode,
            redirect_uri: redirectUri,
        };

        // Выполняем запрос к Keycloak для обмена кода на токен
        const response = await axios.post(tokenUrl, qs.stringify(data), {
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
        });

        const { access_token, refresh_token, id_token } = response.data;

        // Сохраняем токен в куках или в сессии
        res.cookie('access_token', access_token, { httpOnly: true });

        // Редирект на главную страницу после успешной аутентификации
        res.redirect('/');
    } catch (error) {
        console.error('Error fetching token:', error.response ? error.response.data : error.message);
        res.status(500).send('Failed to exchange code for token');
    }
});

app.listen(3000, () => {
    console.log('Server is running on http://localhost:3000');
});