# SIH Demo Guide

## Start backend

```powershell
cd backend
.\venv\Scripts\Activate.ps1
.\venv\Scripts\python.exe -m uvicorn main:app --reload
```

## Start frontend

```powershell
cd frontend
npm install
npm run build
npm start
```

Open `http://localhost:3000`.

## Demo flow

1. Open Analyze Email and upload an EML file.
2. Confirm a unique `INV-...` case is returned.
3. Open Investigation, Threat Graph, Threat Intelligence, AI Investigator, and Reports from the result actions.
4. Ask AI Investigator a question and refresh the page; history is stored in SQLite.
5. Return to Dashboard and refresh; counts and recent cases come from the database.
6. Open Settings to inspect backend, database, and intelligence provider status.

7. In Settings, toggle sensitive-data masking and revisit Dashboard, Investigations, Threat Intelligence, Graph, AI Investigator, and Reports to see presentation values masked while case/evidence identifiers remain intact.

8. Run `backend/venv/Scripts/python.exe backend/train_ml_model.py` before a demo when you want to show the local validation metrics and retraining workflow.

Without API keys, local analysis, correlation, graph, reports, and deterministic AI Investigator remain available. OpenAI and reputation providers are optional enhancements.
