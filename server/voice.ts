import type { Express, Request, Response } from "express";
import { therapeuticAI, ConversationContext } from "./services/openai";

export function registerVoiceRoutes(app: Express) {

  // Process voice message and generate response
  app.post('/api/voice/process', async (req: Request, res: Response): Promise<any> => {
    try {
      const { message, context } = req.body as { message: string; context: ConversationContext };
      
      if (!message || typeof message !== 'string') {
        return res.status(400).json({ error: 'Message is required' });
      }

      if (!context) {
        return res.status(400).json({ error: 'Patient context is required' });
        
      }

      console.log('Processing voice message:', message);

      // Generate compassionate response based on context
      const response = await therapeuticAI.generateResponse(
        message,
        context
      );

      res.json(response);
      
    } catch (error) {
      console.error('Voice processing error:', error);
      res.status(500).json({ 
        error: 'Failed to process voice message',
        message: "I'm here with you. You're safe. Let's take some deep breaths together."
      });
    }
  });

  // Get conversation history for current session
  app.get('/api/voice/history', async (req, res) => {
    try {
      // In a real implementation, this would fetch from database
      // For now, return empty array as sessions are client-side
      res.json({ messages: [] });
    } catch (error) {
      console.error('Failed to fetch conversation history:', error);
      res.status(500).json({ error: 'Failed to fetch conversation history' });
    }
  });

  // Emergency response endpoint
  app.post('/api/voice/emergency', async (req, res) => {
    try {
      const { message } = req.body;
      
      console.log('Emergency detected:', message);
      
      // Generate immediate calming emergency response
      const emergencyResponse = {
        response: "I understand you're feeling very distressed right now. You are safe. I'm here with you. Let's focus on breathing together - in slowly through your nose, and out slowly through your mouth. You're going to be okay.",
        suggestedActivity: "emergency_breathing",
        followUpQuestions: ["Can you take a slow, deep breath with me?", "Let's count together - 1, 2, 3..."],
        redirectionType: "emergency_calming"
      };

      res.json({
        aiResponse: emergencyResponse.response,
        isEmergency: true,
        suggestedActivity: emergencyResponse.suggestedActivity,
        followUpQuestions: emergencyResponse.followUpQuestions,
        redirectionType: emergencyResponse.redirectionType
      });
      
    } catch (error) {
      console.error('Emergency response error:', error);
      res.status(500).json({ 
        error: 'Failed to generate emergency response',
        aiResponse: "You are safe. I'm here with you. Take slow, deep breaths. Everything is going to be okay."
      });
    }
  });
}