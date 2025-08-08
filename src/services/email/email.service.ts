import nodemailer from 'nodemailer';
import { EmailOptions } from './email.type';
import Config from '@config/dotenv.config';
import fs from 'fs';
import path from 'path';
import Handlebars from 'handlebars';
import juice from 'juice';
import { ServerError } from '@middlewares/error.middleware';

const compileTemplate = (
  templateName: string,
  placeholders?: Record<string, string>
): string => {
  const filePath = path.join(
    __dirname,
    '../../../templates',
    `${templateName}.html`
  );
  const templateContent = fs.readFileSync(filePath, 'utf-8');
  const template = Handlebars.compile(templateContent);
  let compiledHtml = template(placeholders);

  compiledHtml = juice(compiledHtml);

  return compiledHtml;
};

const sendEmail = async (options: EmailOptions): Promise<void> => {
  try {
    const user = Config.SMTP.user;
    const pass = Config.SMTP.password;
    const host = Config.SMTP.service;
    const port = parseInt(Config.SMTP.port || '587', 10);
    const secure = Config.SMTP.secure;

    const transporter = nodemailer.createTransport({
      service: host,
      port: port,
      secure: secure,
      auth: {
        user: user,
        pass: pass,
      },
    });

    const html = compileTemplate(options.templateName, options.placeholders);

    const mailOptions = {
      from: `"${Config.CompanyName}" <${user}>`,
      to: options.to,
      subject: options.subject,
      html: html,
    };

    const info = await transporter.sendMail(mailOptions);
    console.log('Email sent:', info.response);
  } catch (error: any) {
    console.error('Error sending email:', error.message);
    throw new ServerError('Failed to send email', error);
  }
};

export default sendEmail;
