<?php
/**
 * BotGuard Demo Integration
 *
 * This file shows a minimal end-to-end integration with FraudGuard BotGuard:
 *
 *  1. A simple HTML form (name, email, message).
 *  2. BotGuard protects the form on the client side (human challenge).
 *  3. When the human challenge is passed, BotGuard adds a botguard_token to the form.
 *  4. On submit, this PHP script verifies the token with FraudGuard's /botguard/token/verify API.
 *
 */

/**
 * IMPORTANT:
 * FraudGuard API credentials - Get from https://app.fraudguard.io/keys
*/
$fgUser = getenv('FRAUDGUARD_API_USER') ?: '';
$fgPass = getenv('FRAUDGUARD_API_PASS') ?: '';

// Simple variables to hold status for this demo
$successMessage = '';
$errorMessage   = '';

// Handle POST (form submission)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {

    // 1) Read the BotGuard token from the form
    $botguardToken = isset($_POST['botguard_token']) ? trim($_POST['botguard_token']) : '';

    if ($botguardToken === '') {
        $errorMessage = 'BotGuard verification is required. Please click "Verify with BotGuard" and try again.';
    } else {

        // 2) Verify the token with FraudGuard BotGuard API (server-side)
        //    We use HTTP Basic Auth with your FraudGuard API credentials.
        if (empty($fgUser) || empty($fgPass)) {
            $errorMessage = 'BotGuard verification could not run because FRAUDGUARD_API_USER / FRAUDGUARD_API_PASS are not configured on the server (set them as environment variables).';
        } else {
            $verifyUrl = 'https://api.fraudguard.io/botguard/token/verify?token=' . urlencode($botguardToken);

            $ch = curl_init();
            curl_setopt_array($ch, [
                CURLOPT_URL            => $verifyUrl,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_USERPWD        => $fgUser . ':' . $fgPass,
                CURLOPT_HTTPAUTH       => CURLAUTH_BASIC,
                CURLOPT_TIMEOUT        => 10,
            ]);

            $responseBody = curl_exec($ch);
            $httpCode     = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $curlError    = curl_error($ch);

            if ($responseBody === false && !$curlError) {
                $curlError = 'Unknown cURL error';
            }

            $json = null;
            if (is_string($responseBody) && $responseBody !== '') {
                $json = json_decode($responseBody, true);
                if (!is_array($json)) {
                    $json = null;
                }
            }

            curl_close($ch);

            if ($curlError) {
                $errorMessage = 'Error contacting BotGuard verify API: ' . htmlspecialchars($curlError);
            } else {
                /**
                 * For this demo, we treat the token as valid only when the verify API returns
                 * HTTP 200 AND a JSON body with { "valid": true }.
                 */
                if ($httpCode === 200 && is_array($json) && isset($json['valid']) && $json['valid'] === true) {
                    // At this point, BotGuard has confirmed this is a human.
                    // Here you would perform your real business logic:
                    //   - send an email
                    //   - create an account
                    //   - allow access to a protected action
                    // For this demo, we just show a success message.

                    $successMessage = '✅ BotGuard verification succeeded. This message was only sent after a human completed the challenge.';
                } elseif ($httpCode === 401) {
                    $errorMessage = 'BotGuard verification failed (HTTP 401). Check your FraudGuard API username/password.';
                } elseif ($httpCode === 200 && is_array($json) && isset($json['valid']) && $json['valid'] === false) {
                    if (isset($json['error']) && $json['error'] === 'expired') {
                        $errorMessage = 'BotGuard verification failed. The token is expired — please run the challenge again.';
                    } else {
                        $errorMessage = 'BotGuard verification failed. The token is invalid — please run the challenge again.';
                    }
                } else {
                    $errorMessage = 'BotGuard verification failed (HTTP ' . $httpCode . '). Please try again.';
                }
            }
        }
    }
}

// Helper for safe HTML output
function h($value) {
    return htmlspecialchars($value ?? '', ENT_QUOTES, 'UTF-8');
}

// Preserve form fields after submit (for demo only)
$name    = isset($_POST['name'])    ? $_POST['name']    : '';
$email   = isset($_POST['email'])   ? $_POST['email']   : '';
$message = isset($_POST['message']) ? $_POST['message'] : '';

?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>FraudGuard BotGuard Demo</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <!-- Tiny bit of styling to make the demo readable -->
    <style>
        body {
            font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            background: #f5f7fb;
            margin: 0;
            padding: 0;
        }
        .wrapper {
            max-width: 720px;
            margin: 40px auto;
            background: #ffffff;
            border-radius: 8px;
            padding: 24px 28px 32px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.08);
        }
        h1 {
            margin-top: 0;
            font-size: 26px;
        }
        p.lead {
            color: #555;
            font-size: 15px;
            line-height: 1.5;
        }
        .notice {
            font-size: 13px;
            color: #777;
            margin-top: 4px;
        }
        .alert {
            padding: 10px 12px;
            border-radius: 4px;
            margin-bottom: 16px;
            font-size: 14px;
        }
        .alert-success {
            background: #e6f6ea;
            color: #216e39;
            border: 1px solid #c2e4ca;
        }
        .alert-error {
            background: #ffecec;
            color: #b91c1c;
            border: 1px solid #f5b7b7;
        }
        label {
            display: block;
            font-size: 14px;
            margin-bottom: 4px;
            font-weight: 600;
        }
        input[type="text"],
        input[type="email"],
        textarea {
            width: 100%;
            box-sizing: border-box;
            padding: 8px 10px;
            margin-bottom: 12px;
            border-radius: 4px;
            border: 1px solid #ccc;
            font-size: 14px;
        }
        textarea {
            min-height: 120px;
            resize: vertical;
        }
        .botguard-section {
            border-top: 1px dashed #ddd;
            padding-top: 14px;
            margin-top: 8px;
            margin-bottom: 16px;
        }
        .botguard-section p {
            margin: 0 0 6px;
            font-size: 13px;
            color: #555;
        }
        .botguard-badge {
            display: inline-flex;
            align-items: center;
            font-size: 12px;
            padding: 4px 8px;
            border-radius: 12px;
            background: #eef4ff;
            color: #1d4ed8;
            margin-bottom: 8px;
        }
        .botguard-badge span {
            margin-left: 4px;
        }
        button[type="submit"] {
            background: #2563eb;
            color: #fff;
            border: none;
            padding: 10px 18px;
            font-size: 14px;
            border-radius: 4px;
            cursor: pointer;
        }
        button[type="submit"]:hover {
            background: #1d4ed8;
        }
        small#botguard-status {
            display: block;
            margin-top: 6px;
            font-size: 12px;
            color: #777;
        }
        a {
            color: #2563eb;
            text-decoration: none;
        }
        a:hover {
            text-decoration: underline;
        }
        code {
            font-size: 12px;
            background: #f0f3fa;
            padding: 2px 4px;
            border-radius: 3px;
        }
    </style>
</head>
<body>
<div class="wrapper">
    <h1>FraudGuard BotGuard – PHP Demo</h1>
    <p class="lead">
        This page shows a <strong>minimal integration</strong> of the
        <strong>FraudGuard BotGuard human verification API</strong>.
        Before this form is processed, the user must pass a short, mobile-friendly
        human challenge that <em>AI agents and bots can’t solve</em>.
    </p>

    <?php if ($successMessage): ?>
        <div class="alert alert-success"><?php echo h($successMessage); ?></div>
    <?php endif; ?>

    <?php if ($errorMessage): ?>
        <div class="alert alert-error"><?php echo h($errorMessage); ?></div>
    <?php endif; ?>

    <form id="botguard-demo-form" method="post" action="">

        <label for="name">Name</label>
        <input type="text" name="name" id="name" value="<?php echo h($name); ?>" placeholder="Jane Doe">

        <label for="email">Email</label>
        <input type="email" name="email" id="email" value="<?php echo h($email); ?>" placeholder="you@example.com">

        <label for="message">Message</label>
        <textarea name="message" id="message" placeholder="Your message..."><?php echo h($message); ?></textarea>

        <div class="botguard-section">
            <p>
                Before this form is submitted, BotGuard will run a quick human verification
                challenge on your phone. On desktop, you’ll see a QR code to scan.
            </p>
            <p style="font-size:12px; color:#666;">
                Learn more about BotGuard:
                <a href="https://fraudguard.io/botguard" target="_blank">fraudguard.io/botguard</a>
            </p>

            <!-- BotGuard will fill this field once the challenge is passed -->
            <input type="hidden" name="botguard_token" id="botguard_token" value="">

            <!-- Single submit button: BotGuard intercepts and runs first, then the form posts here -->
            <button type="submit" id="botguard-submit">
                Verify with BotGuard &amp; Send
            </button>

            <small id="botguard-status">
                Not verified yet. Click the button above to start BotGuard.
            </small>
        </div>
    </form>

    <hr style="margin:24px 0; border:none; border-top:1px solid #eee;">

    <div style="background:#f8f9fc; border:1px solid #e2e8f0; padding:16px 18px; border-radius:6px; margin-bottom:22px;">
        <h3 style="margin-top:0; font-size:18px;">🔄 Resetting BotGuard Verification</h3>
        <p style="font-size:14px; color:#555; line-height:1.5;">
            BotGuard uses <strong>session persistence</strong> to keep real users from solving repeated challenges.
            If the challenge does not appear, here are the three easiest ways to force a new verification:
        </p>

        <h4 style="font-size:15px; margin-bottom:6px;">🧹 1) Open This Page in Private / Incognito Mode</h4>
        <p style="font-size:14px; color:#555; margin-top:0;">
            Incognito windows always start with a fresh BotGuard session.<br>
            <strong>Chrome:</strong> New Incognito Window · 
            <strong>Safari:</strong> New Private Window · 
            <strong>Firefox:</strong> New Private Window
        </p>

        <h4 style="font-size:15px; margin-bottom:6px;">🍪 2) Clear Cookies for This Site</h4>
        <p style="font-size:14px; color:#555; margin-top:0;">
            Removing cookies resets the BotGuard session token.  
            <br><strong>Desktop:</strong> Click the 🔒 in the address bar → Cookies / Site Settings → Remove cookies for this site.  
            <br><strong>Safari (Mac):</strong> Preferences → Privacy → Manage Website Data → Search this site → Remove.
        </p>

        <h4 style="font-size:15px; margin-bottom:6px;">🌐 3) Use a Different Browser</h4>
        <p style="font-size:14px; color:#555; margin-top:0;">
            BotGuard sessions do not carry across browsers.  
            Testing in Chrome, Safari, Firefox, or Edge will always produce a fresh challenge.
        </p>
    </div>
</div>

<!-- BotGuard client script (hosted by FraudGuard) -->
<script src="https://api.fraudguard.io/js/botguard.js?v=1"></script>
<script>
// Minimal client-side integration with the BotGuard widget.
// This assumes BotGuard.js provides BotGuard.create() and bg.attachToForm().

(function () {
    if (typeof BotGuard === 'undefined') {
        console.error('BotGuard library failed to load.');
        return;
    }

    // Create a BotGuard instance pointing at the public FraudGuard API.
    var bg = BotGuard.create({
        apiBase: 'https://api.fraudguard.io'
    });

    // Attach BotGuard to this form. The widget will:
    //  - intercept the form submit,
    //  - run the human challenge,
    //  - populate the hidden #botguard_token field on success,
    //  - then allow the form to submit back to this PHP script.
    bg.attachToForm({
        formSelector: '#botguard-demo-form',
        submitButtonSelector: '#botguard-submit',
        statusSelector: '#botguard-status',
        tokenFieldSelector: '#botguard_token'
    });
})();
</script>

</body>
</html>