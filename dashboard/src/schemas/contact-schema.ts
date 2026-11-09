import { z } from 'zod';

type ContactValidationMessages = {
  emailInvalid: string;
  fullNameRequired: string;
  messageRequired: string;
  messageTooLong: string;
};

// The messages are passed in so the form can show them in the visitor's language.
export function createContactSchema(messages: ContactValidationMessages) {
  return z.object({
    fullName: z.string().min(1, messages.fullNameRequired),
    email: z.string().email(messages.emailInvalid),
    company: z.string().optional(),
    message: z.string().max(200, messages.messageTooLong).min(1, messages.messageRequired),
  });
}

export type ContactInput = z.infer<ReturnType<typeof createContactSchema>>;
