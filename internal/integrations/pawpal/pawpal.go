package pawpal

import (
	"crypto/subtle"
	"fmt"
	"math"
)

type WebhookOutcome string

const (
	WebhookUnauthorized WebhookOutcome = "unauthorized"
	WebhookMalformed    WebhookOutcome = "malformed"
	WebhookApproved     WebhookOutcome = "approved"
)
const maxOrderID = 1<<53 - 1 // translates as 2^53 - 1

type WebhookVerification struct {
	Outcome WebhookOutcome
	OrderID int64
}

func CreateCheckoutURL(orderID int64) string {
	return fmt.Sprintf("https://pawpal.example/checkout?orderId=%d", orderID)
}

func VerifyWebhook(providedKey, expectedKey string, payload any) WebhookVerification {
	if subtle.ConstantTimeCompare([]byte(providedKey), []byte(expectedKey)) != 1 {
		return WebhookVerification{
			Outcome: WebhookUnauthorized,
		}
	}
	payloadRecord, ok := payload.(map[string]any)
	if !ok {
		return WebhookVerification{
			Outcome: WebhookMalformed,
		}
	}
	orderID, ok := payloadRecord["orderId"].(float64)
	if !ok || orderID < 1 || orderID > maxOrderID || orderID != math.Trunc(orderID) { // Final case covers edge cases like orderId = NaN
		return WebhookVerification{
			Outcome: WebhookMalformed,
		}
	}
	status, ok := payloadRecord["status"].(string)
	if !ok || status != "approved" {
		return WebhookVerification{
			Outcome: WebhookMalformed,
		}
	}
	return WebhookVerification{Outcome: WebhookApproved, OrderID: int64(orderID)}
}
