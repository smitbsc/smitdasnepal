# 🏥 MedBot — AI Medical Symptom Chatbot
### College Assignment · INT428

---

## Overview
MedBot is an AI-powered Medical Symptom Analyzer chatbot built with **Node.js + Express** on the backend and **vanilla HTML/CSS/JS** on the frontend. It uses **Google Gemini AI** to analyze user-provided symptoms and generate structured, educational health insights.

> ⚠️ **Educational Use Only.** This chatbot does NOT provide medical diagnosis. Always consult a qualified healthcare professional.

---

## Features
- 🗣️ **Conversational Flow** — Greets user, asks follow-up questions if symptoms are vague
- 📊 **Structured Analysis** — Disease name, probability (%), description, causes, precautions
- 🧠 **Learned Insights** — References similar past cases from session history
- ⚠️ **Severity Check** — Low / Moderate / High with reason
- 🚨 **Emergency Detection** — Immediate alert for chest pain, breathing issues, etc.
- 💡 **Recommendations** — General health advice
- 🔖 **Session Memory** — Maintains last 15 exchanges per user session
- ⚡ **Quick Symptom Chips** — One-click common symptom shortcuts

---

## Project Structure
```
int428/
├── public/
│   ├── index.html        # Frontend UI
│   ├── style.css         # Dark medical theme with glassmorphism
│   └── script.js         # Frontend logic (messaging, session, rendering)
├── src/
│   ├── index.js          # Express server entry point
│   ├── config/
│   │   ├── env.js        # Environment variable loader
│   │   └── systemPrompt.js   # Medical AI system prompt
│   ├── controllers/
│   │   └── chatController.js # Request handlers + session management
│   ├── routes/
│   │   └── chat.js       # API route definitions
│   ├── services/
│   │   └── medAiService.js   # Gemini AI integration
│   └── utils/
│       └── validator.js  # Input validation
├── .env                  # Environment config (add your API key here)
└── package.json
```

---

## Setup & Run

### 1. Install Dependencies
```bash
npm install
```

### 2. Configure API Key
Open `.env` and add your Gemini API key:
```
PORT=3001
GEMINI_API_KEY=your_gemini_api_key_here
```
Get a free key at: https://aistudio.google.com/app/apikey

### 3. Start the Server
```bash
npm run dev     # development (auto-restart)
# or
npm start       # production
```

### 4. Open in Browser
Navigate to: **http://localhost:3001**

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/chat` | Send a message, get AI response |
| `GET`  | `/api/chat/history` | Fetch session history |
| `POST` | `/api/chat/clear` | Clear session memory |
| `GET`  | `/api/chat/stats` | Get session statistics |
| `GET`  | `/api/health` | Server health check |

---

## Response Format (MedBot Output)

```
🧾 Symptom Analysis:
<Brief explanation of what the symptoms may indicate>

📊 Possible Conditions:
1. 🏥 Disease: <Name>
   📈 Probability: <X%>
   📋 Description: <Short explanation>
   🔍 Causes: <List>
   🛡️ Precautions: <List>

🧠 Learned Insight:
<Influence of similar past cases OR "No similar past cases found">

⚠️ Severity Check:
<Low / Moderate / High with reason>

💡 Recommendation:
<General advice>

🚨 Disclaimer:
Educational purposes only. Not a medical diagnosis.
```

---

## Tech Stack
- **Backend:** Node.js, Express.js, ES Modules
- **AI:** Google Gemini 2.5 Flash (`@google/genai`)
- **Frontend:** HTML5, Vanilla CSS (glassmorphism dark theme), Vanilla JS
- **Fonts:** Inter, JetBrains Mono (Google Fonts)

---

*Developed for INT428 — AI Applications in Healthcare*
