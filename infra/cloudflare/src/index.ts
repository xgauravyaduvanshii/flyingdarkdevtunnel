import "dotenv/config";
import { z } from "zod";

const schema = z.object({
  CLOUDFLARE_API_TOKEN: z.string().min(10),
  CLOUDFLARE_ZONE_ID: z.string().min(10),
  BASE_DOMAIN: z.string().min(3),
  TARGET_CNAME: z.string().min(3),
});

const env = schema.parse(process.env);

async function createWildcardCname(): Promise<void> {
  const response = await fetch(
    `https://api.cloudflare.com/client/v4/zones/${env.CLOUDFLARE_ZONE_ID}/dns_records`,
    {
      method: "POST",
      headers: {
        authorization: `Bearer ${env.CLOUDFLARE_API_TOKEN}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        type: "CNAME",
        name: `*.${env.BASE_DOMAIN}`,
        content: env.TARGET_CNAME,
        proxied: true,
      }),
    },
  );

  const body = await response.json();
  if (!response.ok || !body.success) {
    throw new Error(`Cloudflare API error: ${JSON.stringify(body)}`);
  }

  console.log("Wildcard CNAME record created", body.result?.id);
}

createWildcardCname().catch((error) => {
  console.error(error);
  process.exit(1);
});
