(function (module) {
    "use strict";
    const User = require.main.require("./src/user"),
        meta = require.main.require("./src/meta"),
        db = require.main.require("./src/database"),
        vkStrategy = require("./lib/vk-strategy.js"),
        nconf = require.main.require("nconf"),
        async = require.main.require("async");

    const constants = Object.freeze({
        name: "VK",
        admin: {
            route: "/plugins/sso-vk",
            icon: "icon-vk",
        },
        icons: {
            svg: `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 48 48" fill="none"><path d="M0 23.04C0 12.1788 0 6.74826 3.37413 3.37413C6.74826 0 12.1788 0 23.04 0H24.96C35.8212 0 41.2517 0 44.6259 3.37413C48 6.74826 48 12.1788 48 23.04V24.96C48 35.8212 48 41.2517 44.6259 44.6259C41.2517 48 35.8212 48 24.96 48H23.04C12.1788 48 6.74826 48 3.37413 44.6259C0 41.2517 0 35.8212 0 24.96V23.04Z" fill="#0077FF"/><path d="M25.54 34.5801C14.6 34.5801 8.3601 27.0801 8.1001 14.6001H13.5801C13.7601 23.7601 17.8 27.6401 21 28.4401V14.6001H26.1602V22.5001C29.3202 22.1601 32.6398 18.5601 33.7598 14.6001H38.9199C38.0599 19.4801 34.4599 23.0801 31.8999 24.5601C34.4599 25.7601 38.5601 28.9001 40.1201 34.5801H34.4399C33.2199 30.7801 30.1802 27.8401 26.1602 27.4401V34.5801H25.54Z" fill="white"/></svg>`,
        },
    });

    const Plugin = {
        settings: {
            id: process.env.SSO_VK_CLIENT_ID || undefined,
            secret: process.env.SSO_VK_CLIENT_SECRET || undefined,
            autoconfirm: 0,
            disableRegistration: false,
        },
    };

    Plugin.init = function (data, callback) {
        const hostHelpers = require.main.require("./src/routes/helpers");

        hostHelpers.setupAdminPageRoute(
            data.router,
            "/admin/plugins/sso-vk",
            (req, res) => {
                res.render("admin/plugins/sso-vk", {
                    title: constants.name,
                    baseUrl: nconf.get("url"),
                });
            },
        );

        hostHelpers.setupPageRoute(
            data.router,
            "/deauth/vkid",
            [data.middleware.requireUser],
            (req, res) => {
                res.render("plugins/sso-vk/deauth", {
                    service: "VK",
                });
            },
        );

        data.router.post(
            "/deauth/vkid",
            [data.middleware.requireUser, data.middleware.applyCSRF],
            (req, res, next) => {
                Plugin.deleteUserData(
                    {
                        uid: req.user.uid,
                    },
                    (err) => {
                        if (err) {
                            return next(err);
                        }

                        res.redirect(`${nconf.get("relative_path")}/me/edit`);
                    },
                );
            },
        );

        //
        // 🔑 VK ID OAuth маршруты
        //
        // Маршрут инициации: /auth/vkid
        data.router.get("/auth/vkid", (req, res) => {
            Plugin.startVKAuth(req, res);
        });

        // Коллбек маршрут: /auth/vkid/callback
        data.router.get("/auth/vkid/callback", (req, res, next) => {
            Plugin.handleVKCallback(req, res, next);
        });

        meta.settings.get("sso-vk", (_, loadedSettings) => {
            if (loadedSettings.id) {
                Plugin.settings.id = loadedSettings.id;
            }
            if (loadedSettings.secret) {
                Plugin.settings.secret = loadedSettings.secret;
            }
            Plugin.settings.autoconfirm = loadedSettings.autoconfirm === "on";
            Plugin.settings.disableRegistration =
                loadedSettings.disableRegistration === "on";
            callback();
        });
    };

    /**
     * Шаг 1️⃣: Инициирует процесс аутентификации VK ID
     * - Генерирует PKCE параметры
     * - Генерирует state для CSRF защиты
     * - Сохраняет в сессию
     * - Редиректит на VK ID
     */
    Plugin.startVKAuth = function (req, res) {
        if (!Plugin.settings.id || !Plugin.settings.secret) {
            return res
                .status(500)
                .send(
                    "VK ID not configured. Please set SSO_VK_CLIENT_ID and SSO_VK_CLIENT_SECRET",
                );
        }

        try {
            // Генерируем PKCE параметры
            const { codeVerifier, codeChallenge } = vkStrategy.generatePKCE();
            // Генерируем state для CSRF
            const state = vkStrategy.generateState();

            // Сохраняем в сессию для валидации при коллбеке
            req.session.vkidCodeVerifier = codeVerifier; // Для exchange
            req.session.vkidState = state; // Для валидации

            req.session.save((err) => {
                if (err) {
                    console.error("[sso-vk] Session save error:", err);
                    return res.status(500).send("Session error");
                }

                // Генерируем URL авторизации
                const authUrl = vkStrategy.generateAuthorizationURL({
                    clientId: Plugin.settings.id,
                    redirectUri: nconf.get("url") + "/auth/vkid/callback",
                    state: state,
                    codeChallenge: codeChallenge,
                });

                // Редиректим на VK ID
                res.redirect(authUrl);
            });
        } catch (err) {
            console.error("[sso-vk] StartAuth error:", err);
            res.status(500).send("Failed to initiate VK authentication");
        }
    };

    /**
     * Шаг 2️⃣: Обрабатывает коллбек от VK ID
     * - Валидирует state (CSRF)
     * - Обменивает code на token
     * - Получает профиль пользователя
     * - Авторизует пользователя в NodeBB
     */
    Plugin.handleVKCallback = function (req, res, next) {
        const { code, state, error, error_description, device_id } = req.query;

        try {
            // Проверяем ошибку от VK
            if (error) {
                console.error(
                    "[sso-vk] VK auth error:",
                    error,
                    error_description,
                );
                return res
                    .status(400)
                    .send(
                        `VK ID Error: ${error} - ${error_description || "No description"}`,
                    );
            }

            // Проверяем наличие code
            if (!code) {
                console.error("[sso-vk] Missing code parameter");
                return res.status(400).send("Missing authorization code");
            }

            // Проверяем наличие device_id (обязателен по документации VK)
            if (!device_id) {
                console.error("[sso-vk] Missing device_id parameter");
                return res.status(400).send("Missing device_id from VK");
            }

            // ✅ Валидируем state (CSRF защита)
            if (!vkStrategy.validateState(state, req.session.vkidState)) {
                console.error("[sso-vk] State mismatch:", {
                    received: state,
                    expected: req.session.vkidState,
                });
                return res
                    .status(403)
                    .send("Invalid state parameter - CSRF validation failed");
            }

            // Получаем code_verifier из сессии
            const codeVerifier = req.session.vkidCodeVerifier;
            if (!codeVerifier) {
                console.error("[sso-vk] No code_verifier in session");
                return res
                    .status(500)
                    .send("Session error - missing code_verifier");
            }

            // Очищаем временные данные из сессии
            delete req.session.vkidState;
            delete req.session.vkidCodeVerifier;

            // ============================================
            // Шаг 2.1: Обмениваем code на token
            // ============================================
            vkStrategy.exchangeCodeForToken(
                {
                    code: code,
                    codeVerifier: codeVerifier, // ✅ PKCE параметр
                    deviceId: device_id, // ✅ Обязателен
                    clientId: Plugin.settings.id,
                    clientSecret: Plugin.settings.secret,
                    redirectUri: nconf.get("url") + "/auth/vkid/callback",
                },
                (err, tokenData) => {
                    if (err) {
                        console.error("[sso-vk] Token exchange error:", err);
                        return res
                            .status(500)
                            .send("Failed to exchange code for token");
                    }

                    // ============================================
                    // Шаг 2.2: Получаем профиль пользователя
                    // ============================================
                    vkStrategy.getUserProfile(
                        tokenData.access_token,
                        Plugin.settings.id,
                        (err, vkProfile) => {
                            if (err) {
                                console.error(
                                    "[sso-vk] Profile fetch error:",
                                    err,
                                );
                                return res
                                    .status(500)
                                    .send("Failed to fetch user profile");
                            }

                            // Нормализуем профиль
                            const profile =
                                vkStrategy.normalizeProfile(vkProfile);

                            // ============================================
                            // Шаг 2.3: Обрабатываем логин
                            // ============================================
                            Plugin.login(
                                profile.id,
                                profile.displayName,
                                profile.email,
                                profile.photo,
                                (err, user) => {
                                    if (err) {
                                        console.error(
                                            "[sso-vk] Login error:",
                                            err,
                                        );
                                        return next(err);
                                    }

                                    // ============================================
                                    // Шаг 2.4: Авторизуем пользователя в NodeBB
                                    // ============================================
                                    req.login(user, (err) => {
                                        if (err) {
                                            console.error(
                                                "[sso-vk] req.login error:",
                                                err,
                                            );
                                            return next(err);
                                        }

                                        // Перенаправляем на главную
                                        const returnTo =
                                            req.session.returnTo ||
                                            `${nconf.get("relative_path")}/`;
                                        delete req.session.returnTo;
                                        res.redirect(returnTo);
                                    });
                                },
                            );
                        },
                    );
                },
            );
        } catch (err) {
            console.error("[sso-vk] Callback handler error:", err);
            res.status(500).send("Internal server error");
        }
    };

    Plugin.getStrategy = function (strategies, callback) {
        meta.settings.get("sso-vk", function (err, settings) {
            if (!err && settings.id && settings.secret) {
                strategies.push({
                    name: "vkid",
                    url: "/auth/vkid",
                    callbackURL: "/auth/vkid/callback",
                    icon: constants.admin.icon,
                    skipCsrfCheck: true,
                    icons: constants.icons,
                    scope: "emails",
                    labels: {
                        login: "[[vksso:sign-in]]",
                        register: "[[vksso:sign-up]]",
                    },
                });
            }

            callback(null, strategies);
        });
    };

    Plugin.login = function (id, username, email, picture, callback) {
        const autoConfirm = Plugin.settings.autoconfirm;

        Plugin.getUid(id, function (err, uid) {
            if (err) {
                return callback(err);
            }

            if (uid !== null) {
                // Existing User
                callback(null, {
                    uid: uid,
                });
            } else {
                // New User
                const success = async (uid) => {
                    if (autoConfirm) {
                        await User.setUserField(uid, "email", email);
                        await User.email.confirmByUid(uid);
                    }
                    // Save google-specific information to the user
                    User.setUserField(uid, "vkid", id);
                    db.setObjectField("vkid:uid", id, uid);

                    // Save their photo, if present
                    if (picture) {
                        User.setUserField(uid, "uploadedpicture", picture);
                        User.setUserField(uid, "picture", picture);
                    }

                    callback(null, {
                        uid: uid,
                    });
                };

                User.getUidByEmail(email, (err, uid) => {
                    if (err) {
                        return callback(err);
                    }

                    if (!uid) {
                        // Abort user creation if registration via SSO is restricted
                        if (Plugin.settings.disableRegistration) {
                            return callback(
                                new Error(
                                    "[[error:sso-registration-disabled, VK]]",
                                ),
                            );
                        }
                        User.create(
                            {
                                username,
                                email: !autoConfirm ? email : undefined,
                            },
                            (err, uid) => {
                                if (err) {
                                    return callback(err);
                                }

                                success(uid);
                            },
                        );
                    } else {
                        success(uid); // Existing account -- merge
                    }
                });
            }
        });
    };

    Plugin.getUid = function (id, callback) {
        db.getObjectField("vkid:uid", id, (err, uid) => {
            if (err) {
                return callback(err);
            }
            callback(null, uid);
        });
    };

    Plugin.getAssociation = function (data, callback) {
        User.getUserField(data.uid, "vkid", (err, gplusid) => {
            if (err) {
                return callback(err, data);
            }

            if (gplusid) {
                data.associations.push({
                    associated: true,
                    deauthUrl: `${nconf.get("url")}/deauth/vkid`,
                    name: constants.name,
                    icon: constants.admin.icon,
                });
            } else {
                data.associations.push({
                    associated: false,
                    url: `${nconf.get("url")}/auth/vkid`,
                    name: constants.name,
                    icon: constants.admin.icon,
                });
            }

            callback(null, data);
        });
    };

    Plugin.addMenuItem = function (custom_header, callback) {
        custom_header.authentication.push({
            route: constants.admin.route,
            icon: constants.admin.icon,
            name: constants.name,
        });

        callback(null, custom_header);
    };

    Plugin.deleteUserData = function (data, callback) {
        const { uid } = data;

        async.waterfall(
            [
                async.apply(User.getUserField, uid, "vkid"),
                function (oAuthIdToDelete, next) {
                    db.deleteObjectField("vkid:uid", oAuthIdToDelete, next);
                },
                function (next) {
                    db.deleteObjectField(`user:${uid}`, "vkid", next);
                },
            ],
            (err) => {
                if (err) {
                    winston.error(
                        "[sso-vk] Could not remove OAuthId data for uid " +
                            uid +
                            ". Error: " +
                            err,
                    );
                    return callback(err);
                }
                callback(null, uid);
            },
        );
    };

    module.exports = Plugin;
})(module);
