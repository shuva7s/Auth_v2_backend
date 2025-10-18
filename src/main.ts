import * as dotenv from 'dotenv';
dotenv.config();
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import cookieParser from 'cookie-parser';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.use(cookieParser());

  app.enableCors({
    origin: 'http://localhost:3000', // Allow frontend to make requests
    credentials: true,
  });

  // global api prefix
  app.setGlobalPrefix('api');

  await app.listen(process.env.PORT!);
}
bootstrap();
