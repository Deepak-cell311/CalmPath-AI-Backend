import dotenv from 'dotenv/config';
import { Request, Response } from 'express';
import Stripe from 'stripe';
import { storage } from './storage';
import { db } from './db';
import { facilityInvitePurchases } from '../shared/schema';
import { eq } from 'drizzle-orm';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!, {
  apiVersion: '2025-06-30.basil',
});

const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET!;

export default async function webhookHandler(req: Request, res: Response) {
  console.log('🎫 Webhook received:', req.method, req.path);
  console.log('📦 Request headers:', req.headers);
  
  const sig = req.headers['stripe-signature'];

  let event: Stripe.Event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig as string, endpointSecret);
    console.log('✅ Webhook signature verified');
    console.log('📋 Event type:', event.type);
    console.log('📋 Event data:', JSON.stringify(event.data, null, 2));
  } catch (err: any) {
    console.error('❌ Webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  // Handle different events
  switch (event.type) {
    case 'checkout.session.completed':
      const session = event.data.object as Stripe.Checkout.Session;
      console.log('✅ Checkout session completed:', session.id);
      
      // Check if this is an invite purchase
      if (session.metadata?.packageId && session.metadata?.facilityId) {
        console.log('🎫 Processing invite package purchase');
        
        try {
          // Update the purchase status to completed
          await db.update(facilityInvitePurchases)
            .set({
              status: 'completed',
              stripePaymentIntentId: session.payment_intent as string,
              completedAt: new Date()
            })
            .where(eq(facilityInvitePurchases.stripeSessionId, session.id));
          
          console.log('✅ Invite purchase marked as completed');
        } catch (error) {
          console.error('❌ Error updating invite purchase:', error);
        }
      } else {
        // TODO: Handle regular subscription payments
        console.log('📦 Regular subscription payment');
      }
      break;

    case 'invoice.paid':
      console.log('💰 Invoice paid');
      break;

    case 'customer.subscription.deleted':
      console.log('❌ Subscription canceled');
      break;

    default:
      console.log(`Unhandled event type: ${event.type}`);
  }

  res.status(200).json({ received: true });
}
