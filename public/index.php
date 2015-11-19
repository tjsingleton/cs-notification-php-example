<?php
// https://developers.google.com/api-client-library/java/google-http-java-client/reference/1.20.0/com/google/api/client/util/Base64#encodeBase64URLSafeString(byte[])
function urlsafe_b64encode($string) {
    $data = base64_encode($string);
    $data = str_replace(array('+','/', '='), array('-','_',''), $data);       
    return $data;
}

function get_optional_header($key) {
  return isset($_SERVER[$key]) ? $_SERVER[$key] : null;
}

function extract_message(){
  $verb = $_SERVER["REQUEST_METHOD"];
  $sha1 = get_optional_header("HTTP_SHA1");
  $content_type = $_SERVER["CONTENT_TYPE"];
  $request_time =  get_optional_header("HTTP_DATE");
  $path = parse_url($_SERVER["REQUEST_URI"], PHP_URL_PATH);     
  return "$verb\n$sha1\n$content_type\n$request_time\n$path";
}

function calculate_signature($to_sign, $api_key) {
  return urlsafe_b64encode(hash_hmac('sha256', $to_sign, $api_key, true));
}

function get_recieved_signature() { return get_optional_header("HTTP_HMAC"); }

function verify_signature($recieved, $calculated) { return $recieved == $calculated; }

$log_path = "../log";
$api_key = "apikey";

$to_sign = extract_message();
$calculated_signature = calculate_signature($to_sign, $api_key);
$recieved_signature = get_recieved_signature();
$matched = verify_signature($recieved_signature, $calculated_signature);

$json_obj = json_decode(file_get_contents('php://input'), TRUE);

$fp = fopen($log_path . '/request.log', 'a');
fwrite($fp, print_r(array(
  '$_SERVER' => $_SERVER, 
  "JSON" => $json_obj,
  "SIGNATURE INFO" =>  array(    
    "Path" => parse_url($_SERVER["REQUEST_URI"], PHP_URL_PATH),
    "To Sign" => str_replace("\n", "\\n", $to_sign),
    "Received" => $recieved_signature,
    "Calculated" => $calculated_signature,
    "Matched" => $matched ? "TRUE" : "FALSE"
  )
), TRUE));
fclose($fp);

if ($matched) {
  echo "Valid Signature";
} else {
  echo "Invalid Signature";
}