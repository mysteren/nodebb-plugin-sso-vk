/**
 * VK ID OAuth2 Strategy Functions
 * Реализация без Passport - манулаьный OAuth2 флоу согласно документации VK ID
 * https://id.vk.com/about/business/go/docs/ru/vkid/latest/vk-id/connection/start-integration/how-auth-works/auth-flow-web
 */

const crypto = require("crypto");
const https = require("https");
const { URLSearchParams } = require("url");

/**
 * Генерирует PKCE параметры для безопасности
 * @returns {Object} { codeVerifier, codeChallenge }
 */
function generatePKCE() {
    // code_verifier: случайная строка, 43-128 символов
    // Символы: a-z, A-Z, 0-9, _, .
    const codeVerifier = crypto
        .randomBytes(32)
        .toString("base64url")
        .replace(/[^a-zA-Z0-9_.-]/g, "")
        .substring(0, 128);

    // code_challenge: S256 кодирование codeVerifier
    const codeChallenge = crypto
        .createHash("sha256")
        .update(codeVerifier)
        .digest("base64url")
        .replace(/[^a-zA-Z0-9_-]/g, "");

    return { codeVerifier, codeChallenge };
}

/**
 * Генерирует state токен для CSRF защиты
 * @returns {string} Случайный state токен
 */
function generateState() {
    return crypto.randomBytes(32).toString("hex");
}

/**
 * Генерирует URL для редиректа на VK ID авторизацию
 * Шаг 1: Инициирование авторизации
 * @param {Object} config
 *   - clientId: ID приложения VK
 *   - redirectUri: Callback URL
 *   - state: Токен состояния
 *   - codeChallenge: PKCE код-челлендж
 * @returns {string} URL для редиректа
 */
function generateAuthorizationURL(config) {
    const { clientId, redirectUri, state, codeChallenge } = config;

    const params = new URLSearchParams({
        response_type: "code",
        client_id: clientId,
        redirect_uri: redirectUri,
        scope: "email phone",
        state: state,
        code_challenge: codeChallenge,
        code_challenge_method: "S256",
    });

    return `https://id.vk.ru/authorize?${params.toString()}`;
}

/**
 * Валидирует state параметр (CSRF защита)
 * @param {string} receivedState - Полученный state из коллбека
 * @param {string} storedState - State сохраненный в сессии
 * @returns {boolean} Состояние валидно
 */
function validateState(receivedState, storedState) {
    if (!receivedState || !storedState) {
        return false;
    }
    return receivedState === storedState;
}

/**
 * Обменивает authorization code на access token
 * Шаг 2: Обмен кода на токен
 * https://id.vk.ru/oauth2/auth
 * @param {Object} config
 *   - code: Authorization code из коллбека
 *   - codeVerifier: PKCE code verifier
 *   - deviceId: Device ID из коллбека
 *   - clientId: ID приложения VK
 *   - clientSecret: Secret приложения VK
 *   - redirectUri: Callback URL (должен совпадать)
 * @param {Function} callback (err, tokenData)
 */
function exchangeCodeForToken(config, callback) {
    const {
        code,
        codeVerifier,
        deviceId,
        clientId,
        clientSecret,
        redirectUri,
    } = config;

    const params = JSON.stringify({
        grant_type: "authorization_code",
        code: code,
        code_verifier: codeVerifier, // PKCE параметр!
        device_id: deviceId, // ✅ ОБЯЗАТЕЛЕН по документации VK!
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: redirectUri,
    });

    const options = {
        hostname: "id.vk.ru",
        port: 443,
        path: "/oauth2/auth", // ✅ Правильный endpoint
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Content-Length": Buffer.byteLength(params),
        },
    };

    const req = https.request(options, (res) => {
        let data = "";

        res.on("data", (chunk) => {
            data += chunk;
        });

        res.on("end", () => {
            try {
                const response = JSON.parse(data);
                // Проверяем ошибку от VK
                if (response.error) {
                    const errorMsg =
                        response.error_description ||
                        response.error ||
                        "Unknown VK error";
                    return callback(new Error(`VK OAuth Error: ${errorMsg}`));
                }

                // Проверяем наличие токена
                if (!response.access_token) {
                    return callback(
                        new Error("No access token in VK response"),
                    );
                }

                callback(null, response);
            } catch (err) {
                callback(
                    new Error(`Failed to parse VK response: ${err.message}`),
                );
            }
        });
    });

    req.on("error", (err) => {
        callback(new Error(`VK token exchange request failed: ${err.message}`));
    });

    req.write(params);
    req.end();
}

/**
 * Получает профиль пользователя из VK ID
 * Шаг 3: Получение данных пользователя
 * @param {string} accessToken - Access token от VK
 * @param {string} clientId - Client ID приложения (нужен для профиля!)
 * @param {Function} callback (err, profileData)
 */
function getUserProfile(accessToken, clientId, callback) {
    const params = new URLSearchParams({
        access_token: accessToken,
        client_id: clientId,
    }).toString();

    const options = {
        hostname: "id.vk.ru",
        port: 443,
        path: "/oauth2/user_info",
        method: "POST",
        headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": Buffer.byteLength(params),
        },
    };

    const req = https.request(options, (res) => {
        let data = "";

        res.on("data", (chunk) => {
            data += chunk;
        });

        res.on("end", () => {
            try {
                const response = JSON.parse(data);
                // Проверяем ошибку
                if (response.error) {
                    const errorMsg =
                        response.error.error_msg ||
                        response.error ||
                        "Unknown error";
                    return callback(
                        new Error(
                            `VK Profile Error: ${errorMsg}: ${response?.error_description ?? ""}`,
                        ),
                    );
                }

                // Валидируем обязательные поля
                if (!response.user.user_id) {
                    return callback(
                        new Error("No user_id in VK profile response"),
                    );
                }

                callback(null, response);
            } catch (err) {
                callback(
                    new Error(
                        `Failed to parse VK profile response: ${err.message}`,
                    ),
                );
            }
        });
    });

    req.on("error", (err) => {
        callback(new Error(`VK profile request failed: ${err.message}`));
    });

    req.write(params);
    req.end();
}

/**
 * Преобразует VK профиль в формат NodeBB
 * @param {Object} vkProfile - Профиль от VK ID
 * @returns {Object} Нормализованный профиль
 */
function normalizeProfile(vkProfile) {
    return {
        id: String(vkProfile.user.user_id),
        displayName: vkProfile.user.first_name || "vkuser",
        firstName: vkProfile.user.first_name,
        lastName: vkProfile.user.last_name,
        email: vkProfile.user.email || `vk-${vkProfile.user_id}@vk.local`,
        photo: vkProfile.user.avatar,
        raw: vkProfile.user,
    };
}

module.exports = {
    generatePKCE,
    generateState,
    generateAuthorizationURL,
    validateState,
    exchangeCodeForToken,
    getUserProfile,
    normalizeProfile,
};
