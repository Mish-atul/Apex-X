from fastapi import APIRouter, WebSocket, WebSocketDisconnect
import logging
from typing import Dict

from app.engines.intelligence import copilot_rag

logger = logging.getLogger(__name__)

router = APIRouter()

class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}

    async def connect(self, websocket: WebSocket, case_id: str):
        await websocket.accept()
        self.active_connections[case_id] = websocket
        logger.info(f"WebSocket connected for case {case_id}")

    def disconnect(self, case_id: str):
        if case_id in self.active_connections:
            del self.active_connections[case_id]
            logger.info(f"WebSocket disconnected for case {case_id}")

    async def send_message(self, case_id: str, message: dict):
        if case_id in self.active_connections:
            await self.active_connections[case_id].send_json(message)

manager = ConnectionManager()

@router.websocket("/{case_id}")
async def copilot_websocket(websocket: WebSocket, case_id: str):
    await manager.connect(websocket, case_id)
    try:
        while True:
            data = await websocket.receive_text()
            logger.info(f"Received WS message for case {case_id}: {data}")
            
            # Send initial thinking status
            await manager.send_message(case_id, {
                "type": "copilot_status",
                "status": "thinking"
            })
            
            # Stream the LLM response chunk by chunk
            full_response = ""
            try:
                for token in copilot_rag.stream_answer(case_id, data):
                    full_response += token
                    # Stream tokens directly to the UI
                    await manager.send_message(case_id, {
                        "type": "copilot_chunk",
                        "chunk": token
                    })
                
                # Signal completion
                await manager.send_message(case_id, {
                    "type": "copilot_done",
                    "full_message": full_response
                })

            except Exception as e:
                logger.error(f"LLM streaming error for case {case_id}: {e}")
                await manager.send_message(case_id, {
                    "type": "copilot_error",
                    "error": str(e)
                })

    except WebSocketDisconnect:
        manager.disconnect(case_id)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(case_id)
