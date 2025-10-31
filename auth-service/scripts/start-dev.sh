#!/bin/bash

echo "🚀 Iniciando ambiente de desenvolvimento..."

# 1. Verificar e iniciar Docker
if ! docker info &> /dev/null; then
    echo "🐳 Iniciando Docker Desktop..."
    open -a Docker

    # Aguardar Docker ficar pronto
    echo "⏳ Aguardando Docker inicializar..."
    while ! docker info &> /dev/null; do
        sleep 2
        printf "."
    done
    echo ""
    echo "✅ Docker está pronto!"
fi

# 2. Verificar se PostgreSQL já está rodando
if docker ps --format '{{.Names}}' | grep -q "^auth-postgres$"; then
    echo "✅ PostgreSQL já está rodando"
else
    echo "📦 Iniciando PostgreSQL..."
    docker run -d \
        --name auth-postgres \
        -p 5432:5432 \
        -e POSTGRES_DB=ecommerce_auth \
        -e POSTGRES_USER=postgres \
        -e POSTGRES_PASSWORD=postgres \
        postgres:15-alpine
    echo "✅ PostgreSQL iniciado"
fi

# 3. Verificar se Redis já está rodando
if docker ps --format '{{.Names}}' | grep -q "^auth-redis$"; then
    echo "✅ Redis já está rodando"
else
    echo "📦 Iniciando Redis..."
    docker run -d \
        --name auth-redis \
        -p 6379:6379 \
        redis:7-alpine
    echo "✅ Redis iniciado"
fi

# 4. Aguardar serviços ficarem prontos
echo "⏳ Aguardando serviços ficarem prontos..."
sleep 3

# 5. Verificar status
echo ""
echo "📊 Status dos containers:"
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

echo ""
echo "✅ Ambiente pronto!"
echo ""
echo "📋 Próximos passos:"
echo "   1. Rode a aplicação no IntelliJ"
echo "   2. Ou execute: ./mvnw spring-boot:run"
echo ""
echo "🌐 URLs úteis:"
echo "   - API: http://localhost:8081"
echo "   - Swagger: http://localhost:8081/swagger-ui.html"
echo "   - Health: http://localhost:8081/actuator/health"
echo ""
echo "🗄️  Acessar PostgreSQL:"
echo "   docker exec -it auth-postgres psql -U postgres -d ecommerce_auth"
echo ""
echo "🔴 Parar tudo:"
echo "   docker stop auth-postgres auth-redis"