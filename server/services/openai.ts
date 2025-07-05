import OpenAI from "openai";

// the newest OpenAI model is "gpt-4o" which was released May 13, 2024. do not change this unless explicitly requested by the user
const openai = new OpenAI({ 
  apiKey: process.env.OPENAI_API_KEY || process.env.OPENAI_API_KEY_ENV_VAR || "default_key"
});

export interface ConversationContext {
  patientName: string;
  patientAge: number;
  currentMood: string;
  recentNotes?: string[];
  therapeuticPhotos?: string[];
}

export interface ConversationResponse {
  message: string;
  sentiment: 'positive' | 'neutral' | 'negative';
  suggestedMood: 'good' | 'ok' | 'anxious';
  needsStaffAttention: boolean;
}

export class TherapeuticAI {
  private systemPrompt = `You are CalmPathAI, a compassionate therapeutic assistant designed specifically for memory care patients. Your role is to:

1. Provide emotional support and companionship
2. Engage in gentle, calming conversations
3. Help with memory recall through photos and familiar topics
4. Redirect agitation or anxiety toward peaceful thoughts
5. Encourage positive memories and feelings

Guidelines:
- Always speak in a warm, patient, and understanding tone
- Keep responses short and simple (1-2 sentences maximum)
- Use the patient's name frequently to maintain connection
- If the patient seems agitated, gently redirect to calming topics
- Encourage sharing of positive memories
- Ask simple, open-ended questions about family, hobbies, or happy times
- Never argue with confused statements - acknowledge and redirect gently
- If therapeutic photos are mentioned, reference them positively

Remember: You are speaking to someone with memory care needs. Be extra patient, kind, and supportive.`;

  async generateResponse(
    userMessage: string, 
    context: ConversationContext
  ): Promise<ConversationResponse> {
    try {
      const contextPrompt = this.buildContextPrompt(context);
      
      const response = await openai.chat.completions.create({
        model: "gpt-4o",
        messages: [
          { role: "system", content: this.systemPrompt },
          { role: "system", content: contextPrompt },
          { role: "user", content: userMessage }
        ],
        response_format: { type: "json_object" },
        max_tokens: 300,
        temperature: 0.7,
      });

      const result = JSON.parse(response.choices[0].message.content || '{}');
      
      return {
        message: result.message || "I'm here to listen and support you.",
        sentiment: this.validateSentiment(result.sentiment),
        suggestedMood: this.validateMood(result.suggestedMood),
        needsStaffAttention: Boolean(result.needsStaffAttention),
      };
    } catch (error) {
      console.error("Error generating AI response:", error);
      return this.getDefaultResponse(context.patientName);
    }
  }

  async analyzeConversationSentiment(transcript: string): Promise<{
    overallSentiment: string;
    moodAssessment: string;
    keyTopics: string[];
  }> {
    try {
      const response = await openai.chat.completions.create({
        model: "gpt-4o",
        messages: [
          {
            role: "system",
            content: "Analyze this therapeutic conversation transcript. Provide overall sentiment, mood assessment, and key topics discussed. Respond in JSON format with fields: overallSentiment, moodAssessment, keyTopics."
          },
          { role: "user", content: transcript }
        ],
        response_format: { type: "json_object" },
      });

      const result = JSON.parse(response.choices[0].message.content || '{}');
      
      return {
        overallSentiment: result.overallSentiment || 'neutral',
        moodAssessment: result.moodAssessment || 'stable',
        keyTopics: result.keyTopics || [],
      };
    } catch (error) {
      console.error("Error analyzing conversation sentiment:", error);
      return {
        overallSentiment: 'neutral',
        moodAssessment: 'stable',
        keyTopics: [],
      };
    }
  }

  private buildContextPrompt(context: ConversationContext): string {
    let prompt = `Patient Context:
- Name: ${context.patientName}
- Age: ${context.patientAge}
- Current mood: ${context.currentMood}`;

    if (context.recentNotes && context.recentNotes.length > 0) {
      prompt += `\n- Recent staff notes: ${context.recentNotes.join('; ')}`;
    }

    if (context.therapeuticPhotos && context.therapeuticPhotos.length > 0) {
      prompt += `\n- Available therapeutic photos: ${context.therapeuticPhotos.join(', ')}`;
    }

    prompt += `\n\nPlease respond in JSON format with: { "message": "your therapeutic response", "sentiment": "positive/neutral/negative", "suggestedMood": "good/ok/anxious", "needsStaffAttention": false }`;

    return prompt;
  }

  private validateSentiment(sentiment: any): 'positive' | 'neutral' | 'negative' {
    if (['positive', 'neutral', 'negative'].includes(sentiment)) {
      return sentiment;
    }
    return 'neutral';
  }

  private validateMood(mood: any): 'good' | 'ok' | 'anxious' {
    if (['good', 'ok', 'anxious'].includes(mood)) {
      return mood;
    }
    return 'ok';
  }

  private getDefaultResponse(patientName: string): ConversationResponse {
    return {
      message: `Hello ${patientName}, I'm here to chat with you. How are you feeling today?`,
      sentiment: 'neutral',
      suggestedMood: 'ok',
      needsStaffAttention: false,
    };
  }
}

export const therapeuticAI = new TherapeuticAI(); 