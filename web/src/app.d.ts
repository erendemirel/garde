declare global {
	namespace App {
		interface Locals {
			user?: {
				id: string;
				email: string;
				is_admin: boolean;
				is_superuser: boolean;
			};
		}
	}
}

export {};

