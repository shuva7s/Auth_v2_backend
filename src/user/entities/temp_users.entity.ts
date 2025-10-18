import {
  Entity,
  PrimaryColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';

@Entity('temp_users')
export class TempUser {
  @PrimaryColumn()
  email: string;

  @Column()
  name: string;

  @Column({ name: 'hashed_password' })
  hashedPassword: string;

  @Column()
  otp: string;

  @Column({ name: 'otp_expires_at' })
  expiresAt: Date;

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt: Date;
}
