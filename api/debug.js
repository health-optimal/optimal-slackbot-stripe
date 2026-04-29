export default function handler(req, res) {
  // Solo permite acceso con un token simple por seguridad
  if (req.query.token !== "diagnostico-temporal-2026") {
    return res.status(403).send("Forbidden");
  }

  const allEnvKeys = Object.keys(process.env).sort();
  const stripeRelated = allEnvKeys.filter((k) =>
    /STRIPE|SLACK|WEBHOOK|SECRET|KEY/i.test(k)
  );

  res.status(200).json({
    runtime: {
      nodeVersion: process.version,
      vercelEnv: process.env.VERCEL_ENV || null,
      vercelRegion: process.env.VERCEL_REGION || null,
      vercelUrl: process.env.VERCEL_URL || null,
    },
    expectedVars: {
      STRIPE_SECRET_KEY: {
        exists: !!process.env.STRIPE_SECRET_KEY,
        length: process.env.STRIPE_SECRET_KEY?.length || 0,
        prefix: process.env.STRIPE_SECRET_KEY?.slice(0, 7) || null,
        startsWithSk: process.env.STRIPE_SECRET_KEY?.startsWith("sk_") || false,
      },
      STRIPE_WEBHOOK_SECRET: {
        exists: !!process.env.STRIPE_WEBHOOK_SECRET,
        length: process.env.STRIPE_WEBHOOK_SECRET?.length || 0,
        prefix: process.env.STRIPE_WEBHOOK_SECRET?.slice(0, 6) || null,
      },
      SLACK_WEBHOOK_URL: {
        exists: !!process.env.SLACK_WEBHOOK_URL,
        length: process.env.SLACK_WEBHOOK_URL?.length || 0,
      },
    },
    matchingKeys: stripeRelated,
    totalEnvVars: allEnvKeys.length,
  });
}
