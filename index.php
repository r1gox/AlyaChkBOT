<?php 
// Habilitar errores
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Configurar la zona horaria
date_default_timezone_set('America/Mexico_City');

// Obtener el token del bot de Telegram
$token = getenv('TELEGRAM_BOT_TOKEN');
if (empty($token)) {
    die("❌ Error: No se encontró el token del bot.");
}

// Obtener las credenciales de la base de datos
$host = getenv('MYSQLHOST');
$user = getenv('MYSQLUSER');
$password = getenv('MYSQLPASSWORD');
$database = getenv('MYSQLDATABASE');
$port = getenv('MYSQLPORT');

// Crear la conexión a la base de datos
$conn = new mysqli($host, $user, $password, $database, $port);
if ($conn->connect_error) {
    die("❌ Error al conectar a la base de datos: " . $conn->connect_error);
}

// Crear tablas si no existen
$sql = "CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL UNIQUE,
    first_name VARCHAR(255) NOT NULL,
    last_name VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)";
if ($conn->query($sql) === FALSE) {
    die("❌ Error al crear la tabla users: " . $conn->error);
}

$sql = "CREATE TABLE IF NOT EXISTS keys_table (
    id INT AUTO_INCREMENT PRIMARY KEY,
    key_value VARCHAR(255) NOT NULL UNIQUE,
    duration INT NOT NULL,
    duration_type ENUM('d', 'h', 'm') NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    used_by BIGINT DEFAULT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)";
if ($conn->query($sql) === FALSE) {
    die("❌ Error al crear la tabla keys_table: " . $conn->error);
}

$sql = "CREATE TABLE IF NOT EXISTS premiums (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL UNIQUE,
    first_name VARCHAR(255) NOT NULL,
    username VARCHAR(255),
    expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)";
if ($conn->query($sql) === FALSE) {
    die("❌ Error al crear la tabla premiums: " . $conn->error);
}

$sql = "CREATE TABLE IF NOT EXISTS message_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT NOT NULL,
    message_id BIGINT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)";
if ($conn->query($sql) === FALSE) {
    die("❌ Error al crear la tabla message_logs: " . $conn->error);
}

// URL base de la API de Telegram
$website = "https://api.telegram.org/bot".$token;

// Obtener los datos enviados por Telegram
$data = file_get_contents("php://input");
if (empty($data)) {
    die("❌ Error: No se recibieron datos de Telegram.");
}

$json = json_decode($data, true);
if (json_last_error() !== JSON_ERROR_NONE) {
    die("❌ Error: Los datos recibidos no son un JSON válido.");
}

// Verificar si el JSON contiene un mensaje
if (isset($json["message"])) {
    $update = $json["message"];
    $chat_id = $update["chat"]["id"];
    $message = $update["text"];
    $message_id = $update["message_id"];
    $id = $update["from"]["id"];
    $Name = $update["from"]["first_name"];

    // Verificar límite de mensajes
    if (!checkMessageLimit($id, $conn, $message_id)) {
        sendMessage($chat_id, "⏳ Por favor, espera 60 segundos antes de enviar otro mensaje.", $message_id);
        exit;
    }

    // Comando /start (disponible para todos)
    if ($message === "/start") {
        $respuesta = "👋 ¡Hola, $Name! Soy un bot simple.\n\n"
            . "Mis comandos disponibles son:\n"
            . "/start - Ver este mensaje.\n"
            . "/claim [key] - Canjear una key de premium.\n"
            . "/vip [id] - Agregar usuario premium (solo para admins).";
        sendMessage($chat_id, $respuesta, $message_id);
    }

    // Comando /genkey (solo para el usuario 1292171163)
    if (strpos($message, "/genkey") === 0) {
        if ($id == 1292171163) {
            $parts = explode(" ", $message);
            if (count($parts) === 2 && preg_match("/^\d+[dhm]$/", $parts[1])) {
                $duration_type = substr($parts[1], -1); // d, h, o m
                $duration = intval(substr($parts[1], 0, -1)); // Número de días, horas o minutos
                $key_value = generateKey(); // Generar una key única

                // Insertar la key en la base de datos
                $sql = "INSERT INTO keys_table (key_value, duration, duration_type) VALUES (?, ?, ?)";
                $stmt = $conn->prepare($sql);
                $stmt->bind_param("sis", $key_value, $duration, $duration_type);
                $stmt->execute();
                $stmt->close();

                // Respuesta al usuario
                $respuesta = "🔑 Key generada:\n\n"
                    . "Key: <code>$key_value</code>\n"
                    . "Duración: $duration $duration_type\n\n"
                    . "⚠️ Esta key solo puede ser usada una vez.";
                sendMessage($chat_id, $respuesta, $message_id);
            } else {
                sendMessage($chat_id, "❌ Formato incorrecto. Usa /genkey [número][d|h|m].", $message_id);
            }
        } else {
            sendMessage($chat_id, "❌ Este comando es solo para administradores.", $message_id);
        }
    }

    // Comando /claim (disponible para todos)
    if (strpos($message, "/claim") === 0) {
        $parts = explode(" ", $message);
        if (count($parts) === 2) {
            $key_value = $parts[1]; // Key proporcionada por el usuario

            // Verificar si el usuario ya es premium
            $sql = "SELECT * FROM premiums WHERE user_id = ?";
            $stmt = $conn->prepare($sql);
            $stmt->bind_param("i", $id);
            $stmt->execute();
            $result = $stmt->get_result();

            if ($result->num_rows > 0) {
                sendMessage($chat_id, "❌ Ya eres premium. No puedes canjear otra key.", $message_id);
            } else {
                // Verificar si la key existe y no ha sido usada
                $sql = "SELECT * FROM keys_table WHERE key_value = ? AND used = FALSE";
                $stmt = $conn->prepare($sql);
                $stmt->bind_param("s", $key_value);
                $stmt->execute();
                $result = $stmt->get_result();

                if ($result->num_rows > 0) {
                    $key_data = $result->fetch_assoc();
                    $duration = $key_data["duration"];
                    $duration_type = $key_data["duration_type"];

                    // Calcular la fecha de expiración
                    $expires_at = date("Y-m-d H:i:s", strtotime("+$duration $duration_type"));

                    // Marcar la key como usada y eliminarla de la base de datos
                    $sql = "UPDATE keys_table SET used = TRUE, used_by = ? WHERE key_value = ?";
                    $stmt = $conn->prepare($sql);
                    $stmt->bind_param("is", $id, $key_value);
                    $stmt->execute();

                    // Guardar al usuario como premium
                    $sql = "INSERT INTO premiums (user_id, first_name, expires_at) VALUES (?, ?, ?)";
                    $stmt = $conn->prepare($sql);
                    $stmt->bind_param("iss", $id, $Name, $expires_at);
                    $stmt->execute();

                    // Respuesta al usuario
                    $respuesta = "🎉 ¡Felicidades, $Name! Ahora eres premium hasta el $expires_at.";
                    sendMessage($chat_id, $respuesta, $message_id);
                } else {
                    sendMessage($chat_id, "❌ Key inválida o ya ha sido usada.", $message_id);
                }
            }
        } else {
            sendMessage($chat_id, "❌ Formato incorrecto. Usa /claim [key].", $message_id);
        }
    }

    // Comando /vip (solo para el usuario 1292171163)
    if (strpos($message, "/vip") === 0) {
        if ($id == 1292171163) {
            $parts = explode(" ", $message);
            if (count($parts) === 2) {
                $user_id_to_add = $parts[1]; // ID del usuario a agregar como premium

                // Verificar si el usuario ya es premium
                $sql = "SELECT * FROM premiums WHERE user_id = ?";
                $stmt = $conn->prepare($sql);
                $stmt->bind_param("i", $user_id_to_add);
                $stmt->execute();
                $result = $stmt->get_result();

                if ($result->num_rows > 0) {
                    sendMessage($chat_id, "❌ Este usuario ya es premium.", $message_id);
                } else {
                    // Guardar al usuario como premium sin expiración
                    $sql = "INSERT INTO premiums (user_id, first_name, expires_at) VALUES (?, 'Usuario agregado manualmente', NULL)";
                    $stmt = $conn->prepare($sql);
                    $stmt->bind_param("i", $user_id_to_add);
                    $stmt->execute();

                    sendMessage($chat_id, "✅ Usuario $user_id_to_add agregado como premium manualmente.", $message_id);
                }
            } else {
                sendMessage($chat_id, "❌ Formato incorrecto. Usa /vip [id].", $message_id);
            }
        } else {
            sendMessage($chat_id, "❌ Este comando es solo para administradores.", $message_id);
        }
    }
}

// Funciones auxiliares

function sendMessage($chat_id, $message, $reply_to_message_id = null) {
    global $website;
    $url = $website."/sendMessage?chat_id=".$chat_id."&text=".urlencode($message)."&parse_mode=HTML";
    if ($reply_to_message_id) {
        $url .= "&reply_to_message_id=".$reply_to_message_id;
    }
    file_get_contents($url);
}

function checkMessageLimit($user_id, $conn, $message_id) {
    // Verificar si el usuario ha enviado un mensaje en los últimos 60 segundos
    $sql = "SELECT * FROM message_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT 1";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("i", $user_id);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        $last_message = $result->fetch_assoc();
        $last_message_time = strtotime($last_message["created_at"]);
        if (time() - $last_message_time < 60) {
            return false;
        }
    }

    // Registrar el nuevo mensaje
    $sql = "INSERT INTO message_logs (user_id, message_id) VALUES (?, ?)";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("ii", $user_id, $message_id);
    $stmt->execute();

    return true;
}

function generateKey() {
    return substr(str_shuffle("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"), 0, 16);
}
?>
