import {email, z} from 'zod'

export const registerSchema = z.object({
    email: z.email(),
    password: z.string().min(6, "Password must be at least 6 characters"),
    name: z.string().min(3, "Name must be at least 3 characters").max(50, "Name must be less than 50 characters")
})

export const loginSchema = z.object({
    email: z.email(),
    password: z.string().min(6),
    // two factor code is optional because it will only be required if the user has 2FA enabled
    twofactorCode: z.string().optional(),
})