import { NextRequest, NextResponse } from "next/server";
import { Resend } from "resend";

export const dynamic = "force-dynamic";

export async function POST(req: NextRequest) {
  try {
    const { name, email, message } = await req.json();

    if (!name || !email || !message) {
      return NextResponse.json(
        { error: "All fields are required" },
        { status: 400 }
      );
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return NextResponse.json(
        { error: "Invalid email address" },
        { status: 400 }
      );
    }

    const resend = new Resend(process.env.RESEND_API_KEY);
    const { error } = await resend.emails.send({
      from: "Argus Contact <onboarding@resend.dev>",
      to: "cto@gaigentic.ai",
      replyTo: email,
      subject: `[Argus Contact] ${name}`,
      html: `
        <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 560px; margin: 0 auto;">
          <div style="padding: 32px 0; border-bottom: 2px solid #00A76F;">
            <h1 style="margin: 0; font-size: 20px; color: #141A21;">New Contact Form Submission</h1>
          </div>
          <div style="padding: 24px 0;">
            <p style="margin: 0 0 16px; font-size: 14px; color: #637381;">
              <strong style="color: #141A21;">Name:</strong> ${name}
            </p>
            <p style="margin: 0 0 16px; font-size: 14px; color: #637381;">
              <strong style="color: #141A21;">Email:</strong> <a href="mailto:${email}" style="color: #00A76F;">${email}</a>
            </p>
            <div style="margin: 24px 0; padding: 20px; background: #F4F6F8; border-radius: 8px; border-left: 3px solid #00A76F;">
              <p style="margin: 0 0 8px; font-size: 12px; font-weight: 600; color: #919EAB; text-transform: uppercase; letter-spacing: 0.05em;">Message</p>
              <p style="margin: 0; font-size: 14px; color: #212B36; line-height: 1.7; white-space: pre-wrap;">${message}</p>
            </div>
          </div>
          <div style="padding: 16px 0; border-top: 1px solid #E5E8EB; font-size: 12px; color: #919EAB;">
            Sent from argusai.xyz contact form
          </div>
        </div>
      `,
    });

    if (error) {
      console.error("Resend error:", error);
      return NextResponse.json(
        { error: "Failed to send message" },
        { status: 500 }
      );
    }

    return NextResponse.json({ success: true });
  } catch (err) {
    console.error("Contact API error:", err);
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    );
  }
}
