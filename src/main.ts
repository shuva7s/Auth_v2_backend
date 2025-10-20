import * as dotenv from 'dotenv';
dotenv.config();
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import cookieParser from 'cookie-parser';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.use(cookieParser());

  app.enableCors({
    origin:
      process.env.NODE_ENV === 'production'
        ? 'https://auth.shuvadeep.site'
        : 'http://localhost:3000',
    credentials: true,
  });

  app.setGlobalPrefix('api');

  await app.listen(process.env.PORT!);
}
bootstrap();
