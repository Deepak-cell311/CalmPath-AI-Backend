import dotenv from 'dotenv/config';
import { Request, Response } from 'express';
import Stripe from 'stripe';
import { storage } from './storage';
import { db } from './db';
import { facilityInvitePurchases, facilityInvites } from '../shared/schema';
import { eq } from 'drizzle-orm';

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!, {
  apiVersion: '2025-06-30.basil',
});

const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET!;

export default async function webhookHandler(req: Request, res: Response) {
  console.log('🎫 Webhook received:', req.method, req.path);
  console.log('📦 Request headers:', req.headers);
  console.log('📦 Request body length:', req.body?.length || 'No body');
  
  const sig = req.headers['stripe-signature'];

  if (!sig) {
    console.error('❌ No Stripe signature found in headers');
    return res.status(400).send('No Stripe signature found');
  }

  let event: Stripe.Event;

  try {
    event = stripe.webhooks.constructEvent(req.body, sig, endpointSecret);
    console.log('✅ Webhook signature verified');
    console.log('📋 Event type:', event.type);
    console.log('📋 Event ID:', event.id);
    console.log('📋 Event data:', JSON.stringify(event.data, null, 2));
  } catch (err: any) {
    console.error('❌ Webhook signature verification failed:', err.message);
    console.error('❌ Error details:', err);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  // Handle different events
  switch (event.type) {
    case 'checkout.session.completed':
      const session = event.data.object as Stripe.Checkout.Session;
      console.log('✅ Checkout session completed:', session.id);
      console.log('📋 Session metadata:', session.metadata);
      console.log('📋 Payment intent:', session.payment_intent);
      console.log('📋 Session subscription:', session.subscription);
      console.log('👤 Session customer:', session.customer);
      
      // Check if this is an invite purchase
      if (session.metadata?.packageId && session.metadata?.facilityId) {
        console.log('🎫 Processing invite package purchase');
        console.log('📦 Package ID:', session.metadata.packageId);
        console.log('🏥 Facility ID:', session.metadata.facilityId);
        console.log('🎫 Invite count:', session.metadata.inviteCount);
        
        try {
          // First, check if the purchase exists
          const [existingPurchase] = await db
            .select()
            .from(facilityInvitePurchases)
            .where(eq(facilityInvitePurchases.stripeSessionId, session.id));

          if (!existingPurchase) {
            console.error('❌ Purchase not found for session:', session.id);
            console.error('❌ Available purchases:', await db.select().from(facilityInvitePurchases));
            return res.status(400).json({ error: 'Purchase not found' });
          }

          console.log('✅ Found existing purchase:', existingPurchase.id);

          // Update the purchase status to completed
          await db.update(facilityInvitePurchases)
            .set({
              status: 'completed',
              stripePaymentIntentId: session.payment_intent as string,
              completedAt: new Date()
            })
            .where(eq(facilityInvitePurchases.stripeSessionId, session.id));
          
          console.log('✅ Invite purchase marked as completed');

          // Check if invites already exist for this purchase to avoid duplicates
          const existingInvites = await db
            .select()
            .from(facilityInvites)
            .where(eq(facilityInvites.purchaseId, existingPurchase.id));

          console.log('📋 Existing invites count:', existingInvites.length);

          if (!existingInvites || existingInvites.length === 0) {
            console.log('🧾 Creating invites for purchase:', existingPurchase.id);
            console.log('🎫 Invite count to create:', existingPurchase.inviteCount);
            console.log('🏥 Facility ID for invites:', existingPurchase.facilityId);
            
            const createdInvites = await storage.createFacilityInvites(
              existingPurchase.facilityId, 
              existingPurchase.id, 
              existingPurchase.inviteCount
            );
            
            console.log('✅ Invites created successfully:', createdInvites.length);
            console.log('🎫 First few invite codes:', createdInvites.slice(0, 3).map(invite => invite.inviteCode));
          } else {
            console.log('ℹ️ Invites already exist for purchase:', existingPurchase.id);
            console.log('🎫 Existing invite codes:', existingInvites.slice(0, 3).map(invite => invite.inviteCode));
          }
        } catch (error) {
          console.error('❌ Error processing invite purchase:', error);
          console.error('❌ Error stack:', error instanceof Error ? error.stack : 'No stack trace');
          return res.status(500).json({ error: 'Failed to process invite purchase' });
        }
      } 
      // Handle regular subscription payments
      else if (session.subscription && session.customer) {
        console.log('💳 Processing regular subscription payment');
        console.log('📝 Session metadata:', session.metadata);
        console.log('📝 Session subscription:', session.subscription);
        console.log('👤 Session customer:', session.customer);

        const userId = session.metadata?.userId;
        console.log('🔍 Looking for userId in metadata:', userId);
        
        if (userId) {
          console.log('✅ Found userId, updating database for user:', userId);
          try {
            await storage.updateUserStripeCustomerId(userId, session.customer as string);
            await storage.updateUserStripeSubscriptionId(userId, session.subscription as string);
            await storage.updateUserSubscriptionStatus(userId, 'active');
            console.log('✅ Database updated successfully for user:', userId);
          } catch (dbError) {
            console.error('❌ Database update failed for user:', userId, 'Error:', dbError);
          }
        } else {
          console.log('❌ No userId found in session metadata');
        }
      } else {
        console.log('📦 Unknown checkout session type - not an invite purchase or subscription');
        console.log('📋 Session metadata:', session.metadata);
      }
      break;

    case 'customer.subscription.updated':
      const subscription = event.data.object as Stripe.Subscription;
      console.log('📝 Subscription updated:', subscription.id);
      console.log('📝 Subscription metadata:', subscription.metadata);

      const subUserId = subscription.metadata?.userId;
      if (subUserId) {
        console.log('✅ Updating subscription status for user:', subUserId, 'to:', subscription.status);
        try {
          await storage.updateUserSubscriptionStatus(subUserId, subscription.status);
        } catch (dbError) {
          console.error('❌ Database update failed for user:', subUserId, 'Error:', dbError);
        }
      } else {
        console.log('❌ No userId found in subscription metadata');
      }
      break;

    case 'customer.subscription.deleted':
      const deletedSubscription = event.data.object as Stripe.Subscription;
      console.log('🗑️ Subscription deleted:', deletedSubscription.id);
      console.log('📝 Deleted subscription metadata:', deletedSubscription.metadata);

      const deletedUserId = deletedSubscription.metadata?.userId;
      if (deletedUserId) {
        console.log('✅ Updating subscription status for user:', deletedUserId, 'to: canceled');
        try {
          await storage.updateUserSubscriptionStatus(deletedUserId, 'canceled');
        } catch (dbError) {
          console.error('❌ Database update failed for user:', deletedUserId, 'Error:', dbError);
        }
      } else {
        console.log('❌ No userId found in deleted subscription metadata');
      }
      break;

    case 'invoice.payment_succeeded':
      const invoice = event.data.object as Stripe.Invoice;
      console.log('💰 Invoice payment succeeded:', invoice.id);
      console.log('📝 Invoice metadata:', invoice.metadata);
      break;

    case 'invoice.payment_failed':
      const failedInvoice = event.data.object as Stripe.Invoice;
      console.log('❌ Invoice payment failed:', failedInvoice.id);
      console.log('📝 Failed invoice metadata:', failedInvoice.metadata);

      const failedUserId = failedInvoice.metadata?.userId;
      if (failedUserId) {
        console.log('✅ Updating subscription status for user:', failedUserId, 'to: past_due');
        try {
          await storage.updateUserSubscriptionStatus(failedUserId, 'past_due');
        } catch (dbError) {
          console.error('❌ Database update failed for user:', failedUserId, 'Error:', dbError);
        }
      } else {
        console.log('❌ No userId found in failed invoice metadata');
      }
      break;

    case 'invoice.paid':
      console.log('💰 Invoice paid');
      break;

    default:
      console.log(`Unhandled event type: ${event.type}`);
  }

  console.log('✅ Webhook processed successfully');
  res.status(200).json({ received: true });
}
