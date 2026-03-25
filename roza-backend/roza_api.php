<?php
header("Content-Type: application/json");

// -------------------- CONFIG via ENV --------------------
$DB_HOST        = getenv('DB_HOST');
$DB_USER        = getenv('DB_USER');
$DB_PASS        = getenv('DB_PASS');
$DB_NAME        = getenv('DB_NAME');
$PAYSTACK_SECRET = getenv('PAYSTACK_SECRET');

$SMTP_HOST      = getenv('SMTP_HOST');
$SMTP_PORT      = getenv('SMTP_PORT');
$SMTP_USER      = getenv('SMTP_USER');
$SMTP_PASS      = getenv('SMTP_PASS');
$SENDER_EMAIL   = getenv('SENDER_EMAIL');
$SENDER_NAME    = getenv('SENDER_NAME');

// -------------------- PHPMailer --------------------
require_once __DIR__ . '/PHPMailer/PHPMailer.php';
require_once __DIR__ . '/PHPMailer/SMTP.php';
require_once __DIR__ . '/PHPMailer/Exception.php';

// -------------------- CONNECT DB (SUPABASE POSTGRES) --------------------
try {
  $conn = new PDO(
    "pgsql:host=$DB_HOST;port=5432;dbname=$DB_NAME;sslmode=require",
    $DB_USER,
    $DB_PASS
);
$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    echo json_encode(["success"=>false,"message"=>"DB connection failed"]);
    exit;
}

// -------------------- INPUT --------------------
$input = json_decode(file_get_contents("php://input"), true);
$action = $_GET['action'] ?? $_POST['action'] ?? $input['action'] ?? '';

// -------------------- ROUTER --------------------
switch($action){
    case "signup": signupUser($input); break;
    case "login": loginUser($input); break;
    case "verify": verifyPayment($input); break;
    case "get": getSubscription(); break;
    case "send_otp": sendOTP($input); break;
    case "verify_otp": verifyOTP($input); break;
    case "reset_password": resetPassword($input); break;
    default: echo json_encode(["success"=>false,"message"=>"Invalid action"]); break;
}

// -------------------- SIGNUP --------------------
function signupUser($data){
    global $conn;

    $name = trim($data['name'] ?? '');
    $email = trim($data['email'] ?? '');
    $phone = trim($data['phone'] ?? '');
    $password = $data['password'] ?? '';

    if(!$name || !$email || !$phone || !$password){
        echo json_encode(["success"=>false,"message"=>"All fields required"]);
        exit;
    }

    $stmt = $conn->prepare("SELECT id FROM users WHERE email=:email");
    $stmt->execute(['email'=>$email]);

    if($stmt->fetch()){
        echo json_encode(["success"=>false,"message"=>"Email already exists"]);
        exit;
    }

    $uid = uniqid("roza_",true);
    $hashed = password_hash($password,PASSWORD_DEFAULT);

    $stmt = $conn->prepare("INSERT INTO users(uid,email,name,password,phone) VALUES(:uid,:email,:name,:password,:phone)");
    $ok = $stmt->execute([
        'uid'=>$uid,
        'email'=>$email,
        'name'=>$name,
        'password'=>$hashed,
        'phone'=>$phone
    ]);

    echo json_encode($ok ? ["success"=>true,"uid"=>$uid] : ["success"=>false]);
}

// -------------------- LOGIN --------------------
function loginUser($data){
    global $conn;

    $email = trim($data['email'] ?? '');
    $password = $data['password'] ?? '';

    $stmt = $conn->prepare("SELECT * FROM users WHERE email=:email");
    $stmt->execute(['email'=>$email]);

    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if($user && password_verify($password,$user['password'])){
        unset($user['password']);
        echo json_encode(["success"=>true,"user"=>$user]);
    } else {
        echo json_encode(["success"=>false,"message"=>"Invalid credentials"]);
    }
}

// -------------------- SEND OTP --------------------
function sendOTP($data){
    global $conn, $SMTP_HOST, $SMTP_PORT, $SMTP_USER, $SMTP_PASS, $SENDER_EMAIL, $SENDER_NAME;

    $email = trim($data['email'] ?? '');

    $stmt = $conn->prepare("SELECT id FROM users WHERE email=:email");
    $stmt->execute(['email'=>$email]);

    if(!$stmt->fetch()){
        echo json_encode(["success"=>true]);
        exit;
    }

    $otp = rand(1000,9999);
    $expiry = date("Y-m-d H:i:s", strtotime("+5 minutes"));

    $stmt = $conn->prepare("UPDATE users SET otp=:otp, otp_expiry=:exp WHERE email=:email");
    $stmt->execute([
        'otp'=>$otp,
        'exp'=>$expiry,
        'email'=>$email
    ]);

    $mail = new PHPMailer\PHPMailer\PHPMailer(true);
    try{
        $mail->isSMTP();
        $mail->Host = $SMTP_HOST;
        $mail->SMTPAuth = true;
        $mail->Username = $SMTP_USER;
        $mail->Password = $SMTP_PASS;
        $mail->SMTPSecure = 'ssl';
        $mail->Port = $SMTP_PORT;

        $mail->setFrom($SENDER_EMAIL, $SENDER_NAME);
        $mail->addAddress($email);
        $mail->Subject = "Your OTP Code";
        $mail->isHTML(true);
        $mail->Body = "<h3>Password Reset</h3><h1>$otp</h1>";

        $mail->send();
        echo json_encode(["success"=>true]);
    } catch(Exception $e){
        echo json_encode(["success"=>false,"message"=>$mail->ErrorInfo]);
    }
}

// -------------------- VERIFY OTP --------------------
function verifyOTP($data){
    global $conn;

    $stmt = $conn->prepare("SELECT otp, otp_expiry FROM users WHERE email=:email");
    $stmt->execute(['email'=>$data['email']]);

    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if($row && $row['otp']==$data['otp'] && $row['otp_expiry'] > date("Y-m-d H:i:s")){
        echo json_encode(["success"=>true]);
    } else {
        echo json_encode(["success"=>false]);
    }
}

// -------------------- RESET PASSWORD --------------------
function resetPassword($data){
    global $conn;

    $hashed = password_hash($data['password'], PASSWORD_DEFAULT);

    $stmt = $conn->prepare("UPDATE users SET password=:p WHERE email=:e");
    $ok = $stmt->execute([
        'p'=>$hashed,
        'e'=>$data['email']
    ]);

    echo json_encode($ok ? ["success"=>true] : ["success"=>false]);
}

// -------------------- PAYSTACK --------------------
function verifyPayment($data){
    global $conn, $PAYSTACK_SECRET;

    $reference = $data['reference'];

    $curl = curl_init("https://api.paystack.co/transaction/verify/".$reference);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($curl, CURLOPT_HTTPHEADER, ["Authorization: Bearer $PAYSTACK_SECRET"]);
    $response = curl_exec($curl);
    curl_close($curl);

    $result = json_decode($response,true);

    if($result['data']['status'] !== "success"){
        echo json_encode(["success"=>false]);
        return;
    }

    $amount = $result['data']['amount']/100;
    $plan = ($amount == 1755) ? "monthly" : "yearly";
    $expiry = ($plan=="monthly") ? date("Y-m-d H:i:s", strtotime("+1 month")) : date("Y-m-d H:i:s", strtotime("+1 year"));

    $stmt = $conn->prepare("INSERT INTO subscriptions(uid,email,plan,start_date,expiry_date) VALUES(:uid,:email,:plan,:start,:exp)");
    $stmt->execute([
        'uid'=>$data['uid'],
        'email'=>$data['email'],
        'plan'=>$plan,
        'start'=>date("Y-m-d H:i:s"),
        'exp'=>$expiry
    ]);

    echo json_encode(["success"=>true]);
}

// -------------------- GET SUB --------------------
function getSubscription(){
    global $conn;

    $stmt = $conn->prepare("SELECT * FROM subscriptions WHERE uid=:uid ORDER BY id DESC LIMIT 1");
    $stmt->execute(['uid'=>$_GET['uid']]);

    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    echo json_encode($row ?: ["plan"=>null]);
}
?>