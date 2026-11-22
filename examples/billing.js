// Example bundle for JS-Endpoints-Hunter. All secrets are fake.
const API = "/api/v1";

fetch(`${API}/billing/invoices`);
fetch("/api/v1/users/${userId}/orders");
axios.post("/api/v2/payments/charge", { amount: 100 });
axios.get("https://api.example.com/v3/accounts");
const xhr = new XMLHttpRequest();
xhr.open("DELETE", "/api/v1/sessions/current");
$.ajax({ url: "/api/v1/admin/audit", method: "POST" });
$.get("/api/v1/plans");
got.get("https://cdn.example.com/config.json");
const ws = new WebSocket("wss://ws.example.com/socket");
const events = new EventSource("/api/v1/events");
const query = "query Billing { invoices { id total } }";
const graphql = "/api/graphql";
const config = "https://static.example.com/assets/app.json";

// Fake test fixtures, never real credentials.
const awsKey = "AKIAABCDEFGHIJKLMNOP";
const stripeKey = "sk_test_" + "000000000000000000000000";
const githubToken = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";
const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.signature";
const generic = "api_key=abcdefghijklmnop";

//# sourceMappingURL=billing.js.map
