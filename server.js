const express = require('express');
const stripe = require('stripe')('sk_test_51TY3bQF3xe6EYolNpiCuElxszlGT2eQtQR3xX4mxM8XDUHEKQK6Ap4fEEmuGAFaCE28izCYqt8D4mbXpaHQytYBk00mlFmgzNb');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// Create subscription
app.post('/create-subscription', async (req, res) => {
  const { paymentMethodId, priceId, email } = req.body;
  try {
    // Create customer
    const customer = await stripe.customers.create({
      email: email || 'subscriber@nova-ai.com',
      payment_method: paymentMethodId,
      invoice_settings: { default_payment_method: paymentMethodId },
    });

    // Create subscription
    const subscription = await stripe.subscriptions.create({
      customer: customer.id,
      items: [{ price: priceId }],
      payment_settings: {
        payment_method_options: { card: { request_three_d_secure: 'any' } },
        payment_method_types: ['card'],
        save_default_payment_method: 'on_subscription',
      },
      expand: ['latest_invoice.payment_intent'],
    });

    const paymentIntent = subscription.latest_invoice.payment_intent;

    res.json({
      subscriptionId: subscription.id,
      clientSecret: paymentIntent?.client_secret,
      status: subscription.status,
    });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// Health check
app.get('/', (req, res) => res.json({ status: 'N.O.V.A. Backend Online' }));

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`N.O.V.A. Backend running on port ${PORT}`));
