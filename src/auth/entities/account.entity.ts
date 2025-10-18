import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  JoinColumn,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';
import { User } from 'src/user/entities/user.entity';

@Entity('accounts')
export class Account {
  @PrimaryGeneratedColumn('uuid', { name: 'id' })
  id: string;

  @Column({ name: 'provider_id' })
  providerId: string;

  @ManyToOne(() => User, (user) => user.accounts, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id' })
  user: User;

  @Column({ name: 'access_token', nullable: true })
  accessToken?: string;

  @Column({ name: 'refresh_token', nullable: true })
  refreshToken?: string;

  @Column({ name: 'id_token', nullable: true })
  idToken?: string;

  @Column({
    name: 'access_token_expires_at',
    type: 'timestamp',
    nullable: true,
  })
  accessTokenExpiresAt?: Date;

  @Column({
    name: 'refresh_token_expires_at',
    type: 'timestamp',
    nullable: true,
  })
  refreshTokenExpiresAt?: Date;

  @Column({ name: 'scope', nullable: true })
  scope?: string;

  @Column({ name: 'hashed_password', nullable: true })
  hashedPassword?: string;

  @CreateDateColumn({ name: 'created_at' })
  createdAt: Date;

  @UpdateDateColumn({ name: 'updated_at' })
  updatedAt: Date;
}
