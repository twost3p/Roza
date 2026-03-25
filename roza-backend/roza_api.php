<?php
header("Content-Type: application/json");

// -------------------- CONFIG via ENV --------------------
$DB_HOST        = getenv('DB_HOST');
$DB_USER        = getenv('DB_USER');
$DB_PASS        = getenv('DB_PASS');
$DB_NAME        = getenv('DB_NAME');
$PAYSTACK_SECRET = getenv('PAYSTACK_SECRET');

$SMTP_HOST      = getenv('SMTP_HOST');
$SMTP_PORT      = getenv('SMTP_PORT');      // e.g., 465
$SMTP_USER      = getenv('SMTP_USER');      // TurboSMTP username
$SMTP_PASS      = getenv('SMTP_PASS');      // TurboSMTP password
$SENDER_EMAIL   = getenv('SENDER_EMAIL');   // e.g., rozafakebank@gmail.com
$SENDER_NAME    = getenv('SENDER_NAME');    // e.g., Roza

// -------------------- PHPMailer Includes --------------------
require __DIR__ . '/PHPMailer/PHPMailer.php';
require __DIR__ . '/PHPMailer/SMTP.php';
require __DIR__ . '/PHPMailer/Exception.php';
require __DIR__ . '/roza_api.php';

// -------------------- CONNECT DB --------------------
$conn = new mysqli($DB_HOST, $DB_USER, $DB_PASS, $DB_NAME);
if ($conn->connect_error) {
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

    $stmt = $conn->prepare("SELECT id FROM users WHERE email=?");
    $stmt->bind_param("s",$email);
    $stmt->execute();
    $stmt->store_result();
    if($stmt->num_rows > 0){
        echo json_encode(["success"=>false,"message"=>"Email already exists"]);
        exit;
    }

    $uid = uniqid("roza_",true);
    $hashed = password_hash($password,PASSWORD_DEFAULT);
    $stmt = $conn->prepare("INSERT INTO users(uid,email,name,password,phone) VALUES(?,?,?,?,?)");
    $stmt->bind_param("sssss",$uid,$email,$name,$hashed,$phone);
    echo json_encode($stmt->execute() ? ["success"=>true,"uid"=>$uid] : ["success"=>false,"message"=>"Signup failed"]);
}

// -------------------- LOGIN --------------------
function loginUser($data){
    global $conn;

    $email = trim($data['email'] ?? '');
    $password = $data['password'] ?? '';

    if(!$email || !$password){
        echo json_encode(["success"=>false,"message"=>"Email & password required"]);
        exit;
    }

    $stmt = $conn->prepare("SELECT id,uid,name,email,phone,password FROM users WHERE email=?");
    $stmt->bind_param("s",$email);
    $stmt->execute();
    $res = $stmt->get_result();
    if($user = $res->fetch_assoc()){
        if(password_verify($password,$user['password'])){
            unset($user['password']);
            echo json_encode(["success"=>true,"user"=>$user]);
        } else {
            echo json_encode(["success"=>false,"message"=>"Incorrect password"]);
        }
    } else {
        echo json_encode(["success"=>false,"message"=>"User not found"]);
    }
}

// -------------------- SEND OTP --------------------
function sendOTP($data){
    global $conn, $SMTP_HOST, $SMTP_PORT, $SMTP_USER, $SMTP_PASS, $SENDER_EMAIL, $SENDER_NAME;

    $email = trim($data['email'] ?? '');
    if(!$email){
        echo json_encode(["success"=>false,"message"=>"Email required"]);
        exit;
    }

    $stmt = $conn->prepare("SELECT id FROM users WHERE email=?");
    $stmt->bind_param("s",$email);
    $stmt->execute();
    $res = $stmt->get_result();
    if(!$res->fetch_assoc()){
        echo json_encode(["success"=>true,"message"=>"If email exists, OTP sent"]);
        exit;
    }

    $otp = rand(1000,9999);
    $expiry = date("Y-m-d H:i:s", strtotime("+5 minutes"));

    $stmt = $conn->prepare("UPDATE users SET otp=?, otp_expiry=? WHERE email=?");
    $stmt->bind_param("sss",$otp,$expiry,$email);
    $stmt->execute();

    // PHPMailer
    $mail = new PHPMailer\PHPMailer\PHPMailer(true);
    try{
        $mail->isSMTP();
        $mail->Host       = $SMTP_HOST;
        $mail->SMTPAuth   = true;
        $mail->Username   = $SMTP_USER;
        $mail->Password   = $SMTP_PASS;
        $mail->SMTPSecure = 'ssl';
        $mail->Port       = $SMTP_PORT;

        $mail->setFrom($SENDER_EMAIL, $SENDER_NAME);
        $mail->addAddress($email);
        $mail->Subject = "Your OTP Code";
        $mail->isHTML(true);
        $mail->Body = "<h3>Password Reset</h3><p>Your OTP is:</p><h1>$otp</h1><p>Expires in 5 minutes</p>";

        $mail->send();
        echo json_encode(["success"=>true]);
    } catch(Exception $e){
        echo json_encode(["success"=>false,"message"=>$mail->ErrorInfo]);
    }
}

// -------------------- VERIFY OTP --------------------
function verifyOTP($data){
    global $conn;
    $email = trim($data['email'] ?? '');
    $otp   = trim($data['otp'] ?? '');

    $stmt = $conn->prepare("SELECT otp,otp_expiry FROM users WHERE email=?");
    $stmt->bind_param("s",$email);
    $stmt->execute();
    $res = $stmt->get_result();

    if($row = $res->fetch_assoc()){
        if($row['otp'] == $otp && $row['otp_expiry'] > date("Y-m-d H:i:s")){
            echo json_encode(["success"=>true]);
        } else {
            echo json_encode(["success"=>false,"message"=>"Invalid or expired OTP"]);
        }
    } else {
        echo json_encode(["success"=>false,"message"=>"User not found"]);
    }
}

// -------------------- RESET PASSWORD --------------------
function resetPassword($data){
    global $conn;
    $email = trim($data['email'] ?? '');
    $password = $data['password'] ?? '';

    if(!$email || !$password){
        echo json_encode(["success"=>false,"message"=>"Missing data"]);
        exit;
    }

    $hashed = password_hash($password,PASSWORD_DEFAULT);
    $stmt = $conn->prepare("UPDATE users SET password=?, otp=NULL, otp_expiry=NULL WHERE email=?");
    $stmt->bind_param("ss",$hashed,$email);
    echo json_encode($stmt->execute() ? ["success"=>true,"message"=>"Password updated"] : ["success"=>false,"message"=>"Update failed"]);
}

// -------------------- PAYSTACK --------------------
function verifyPayment($data){
    global $conn, $PAYSTACK_SECRET;

    $reference = $data['reference'] ?? '';
    $uid       = $data['uid'] ?? '';
    $email     = $data['email'] ?? '';

    $curl = curl_init("https://api.paystack.co/transaction/verify/".$reference);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($curl, CURLOPT_HTTPHEADER, ["Authorization: Bearer $PAYSTACK_SECRET"]);
    $response = curl_exec($curl);
    curl_close($curl);

    $result = json_decode($response,true);
    if(!$result || $result['data']['status'] !== "success"){
        echo json_encode(["success"=>false,"message"=>"Payment failed"]);
        exit;
    }

    $amount = $result['data']['amount'] / 100;
    $now = date("Y-m-d H:i:s");

    if($amount == 1755){ 
        $plan="monthly"; 
        $expiry=date("Y-m-d H:i:s", strtotime("+1 month")); 
    } elseif($amount == 19500){ 
        $plan="yearly"; 
        $expiry=date("Y-m-d H:i:s", strtotime("+1 year")); 
    } else { 
        echo json_encode(["success"=>false]); 
        exit; 
    }

    $stmt = $conn->prepare("INSERT INTO subscriptions(uid,email,plan,start_date,expiry_date) VALUES(?,?,?,?,?)");
    $stmt->bind_param("sssss",$uid,$email,$plan,$now,$expiry);
    $stmt->execute();
    echo json_encode(["success"=>true]);
}

// -------------------- GET SUB --------------------
function getSubscription(){
    global $conn;
    $uid = $_GET['uid'] ?? '';

    $stmt = $conn->prepare("SELECT * FROM subscriptions WHERE uid=? ORDER BY id DESC LIMIT 1");
    $stmt->bind_param("s",$uid);
    $stmt->execute();
    $res = $stmt->get_result();

    if($row = $res->fetch_assoc()){
        echo json_encode([
            "plan"=>$row['plan'],
            "expiry_date"=>$row['expiry_date'],
            "active"=>$row['expiry_date'] > date("Y-m-d H:i:s")
        ]);
    } else {
        echo json_encode(["plan"=>null]);
    }
}
?>