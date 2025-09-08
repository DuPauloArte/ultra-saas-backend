// backend/server.js

// --- 1. IMPORTAÇÕES ---
import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import stripe from 'stripe';

// --- 2. CONFIGURAÇÃO INICIAL E CONEXÃO COM O BANCO DE DADOS ---
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = 'seu-segredo-super-secreto-e-longo'; 
const stripeInstance = stripe(process.env.STRIPE_SECRET_KEY);

app.use(cors());

// A ROTA DE WEBHOOK DEVE VIR PRIMEIRO, com seu próprio parser de corpo 'raw'
app.post('/api/stripe/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
    const sig = req.headers['stripe-signature'];
    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
    let event;

    try {
        event = stripeInstance.webhooks.constructEvent(req.body, sig, webhookSecret);
    } catch (err) {
        console.log(`❌ Erro no webhook: ${err.message}`);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    // ===================================================================
    //      INÍCIO DA LÓGICA COMPLETA DO WEBHOOK
    // ===================================================================

    // Lide com os diferentes tipos de eventos
    switch (event.type) {
        
        // --- CASO 1: Assinatura bem-sucedida ---
        case 'checkout.session.completed':
            const session = event.data.object;
            console.log(`Webhook recebido: ${event.type}. Processando sessão ${session.id}`);

            try {
                const lineItems = await stripeInstance.checkout.sessions.listLineItems(session.id);
                if (!lineItems.data || lineItems.data.length === 0) {
                    console.error('Erro: Nenhum line_item encontrado na sessão de checkout.');
                    return res.status(400).send('Nenhum line_item encontrado.');
                }
                const priceId = lineItems.data[0].price.id;
                console.log(`Price ID extraído: ${priceId}`);

                // ATENÇÃO: Verifique se os IDs abaixo estão corretos
                const priceIdToPlanMap = {
                    'price_1S4otg38EcxtIJ87v7Q5iwyP': 'Power',    // Substitua pelo seu Price ID do plano Power
                    'price_1S4ouD38EcxtIJ87eaRNGMOW': 'Turbo',    // Substitua pelo seu Price ID do plano Turbo
                    'price_1S4out38EcxtIJ87KG0DUNcf': 'Ultra',    // Substitua pelo seu Price ID do plano Ultra
                    'price_1S4ovp38EcxtIJ8776wx3dum': 'Ultra',    // Substitua pelo seu Price ID do plano Free
                };

                const planName = priceIdToPlanMap[priceId];
                console.log(`Plano correspondente encontrado: ${planName}`);

                if (!planName) {
                    console.error(`ERRO CRÍTICO: Price ID ${priceId} não foi encontrado no mapa de planos.`);
                    return res.status(400).send('Erro de configuração: Price ID não mapeado.');
                }
                
                const userId = session.client_reference_id;
                const stripeCustomerId = session.customer;
                const stripeSubscriptionId = session.subscription;

                console.log(`Pronto para atualizar o usuário. Dados:
                    - UserID: ${userId}
                    - Stripe Customer ID: ${stripeCustomerId}
                    - Stripe Subscription ID: ${stripeSubscriptionId}
                    - Plano: ${planName}`);

                const updatedUser = await User.findByIdAndUpdate(userId, {
                    stripeCustomerId,
                    stripeSubscriptionId,
                    plan: planName,
                    subscriptionStatus: 'active',
                }, { new: true }); // { new: true } retorna o documento atualizado

                if (updatedUser) {
                    console.log(`✅ Usuário ${userId} atualizado com sucesso no banco de dados.`);
                } else {
                    console.error(`❌ Falha ao atualizar o usuário ${userId}. Usuário não encontrado no DB.`);
                }

            } catch (error) {
                console.error('❌ Erro GERAL ao processar checkout.session.completed:', error);
                return res.status(500).send('Erro interno ao processar a assinatura.');
            }
            break;

        // --- CASO 2: Assinatura cancelada ou com falha de pagamento ---
        case 'customer.subscription.deleted':
        case 'customer.subscription.updated':
            const subscription = event.data.object;
            console.log(`Webhook recebido: ${event.type} para a assinatura ${subscription.id}`);

            // Verificamos se o status da assinatura indica que ela não está mais ativa
            if (subscription.status !== 'active' && subscription.status !== 'trialing') {
                try {
                    const stripeCustomerId = subscription.customer;
                    console.log(`Procurando usuário no banco de dados com stripeCustomerId: ${stripeCustomerId}`);

                    // A busca no DB é o ponto mais crítico
                    const userToUpdate = await User.findOne({ stripeCustomerId: stripeCustomerId });

                    if (userToUpdate) {
                        console.log(`Usuário encontrado: ${userToUpdate._id}. Atualizando para o plano Free.`);
                        // Redefinimos o plano do usuário para 'Free'
                        await User.findByIdAndUpdate(userToUpdate._id, {
                            plan: 'Free',
                            subscriptionStatus: 'canceled',
                        });
                        console.log(`✅ Assinatura cancelada com sucesso para o usuário ${userToUpdate._id}.`);
                    } else {
                        // Se chegamos aqui, a busca falhou!
                        console.log(`❌ Nenhum usuário encontrado com o stripeCustomerId: ${stripeCustomerId}`);
                    }
                } catch (error) {
                    console.error('Erro ao processar cancelamento de assinatura:', error);
                    return res.status(500).send('Erro interno ao processar o cancelamento.');
                }
            } else {
                console.log(`Status da assinatura ainda é '${subscription.status}'. Nenhuma ação necessária.`);
            }
            break;


        default:
            // Para qualquer outro evento que não estamos tratando, apenas registramos no log
            console.log(`Evento não tratado: ${event.type}`);
    }

    




    // ===================================================================
    //      FIM DA LÓGICA COMPLETA DO WEBHOOK
    // ===================================================================

    // Responda ao Stripe com um status 200 para confirmar o recebimento do evento
    res.json({ received: true });
});

app.use(express.json());

mongoose.connect(process.env.DATABASE_URL)
    .then(() => console.log('✅ Conectado ao MongoDB Atlas com sucesso!'))
    .catch(err => console.error('❌ Erro ao conectar ao MongoDB:', err));


// --- 3. DEFINIÇÃO DOS MODELS (SCHEMAS) COM MONGOOSE ---

const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true, lowercase: true },
    passwordHash: { type: String, required: true },
    plan: {
        type: String,
        enum: ['Power', 'Turbo', 'Ultra', 'Enterprise', 'Staff', 'Free'],
        default: 'Free' // Todo novo usuário começa no plano Power
    },
    subscriptionStatus: {
        type: String,
        enum: ['active', 'canceled', 'inactive'],
        default: 'active'
    },

    stripeCustomerId: {
        type: String,
        default: null
    },
    stripeSubscriptionId: {
        type: String,
        default: null
    },
}, { timestamps: true });
const User = mongoose.model('User', userSchema);

// Schema para Projetos
const projectSchema = new mongoose.Schema({
    name: { type: String, required: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }
}, { timestamps: true });
const Project = mongoose.model('Project', projectSchema);

// Schema para Leads
const leadSchema = new mongoose.Schema({
    status: { type: String, default: 'novo' },
    receivedAt: { type: Date, default: Date.now },
    projectId: { type: mongoose.Schema.Types.ObjectId, ref: 'Project', required: true },
    nome: { type: String, default: 'N/A' },
    email: { type: String, required: true },
    telefone: { type: String, default: 'N/A' },
    cidade: { type: String, default: 'Não informado' },
    comentarios: [{
        texto: String,
        data: { type: Date, default: Date.now }
    }]
});
const Lead = mongoose.model('Lead', leadSchema);


// --- 4. MIDDLEWARE DE AUTENTICAÇÃO E LÓGICA DE PLANOS ---

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Definição dos limites de cada plano
const planLimits = {
    Free: 100,
    Power: 500,
    Turbo: 2000,
    Ultra: 5000,
    Enterprise: Infinity,
    Staff: Infinity
};

// NOVO MIDDLEWARE: Verifica se o usuário atingiu o limite de leads do mês
const checkLeadLimit = async (req, res, next) => {
    try {
        const { projectId } = req.params;
        const project = await Project.findById(projectId);
        if (!project) {
            return res.status(404).json({ message: 'ID do projeto inválido.' });
        }

        const user = await User.findById(project.userId);
        if (!user || user.subscriptionStatus !== 'active') {
            return res.status(403).json({ message: 'Assinatura inativa.' });
        }

        const limit = planLimits[user.plan];
        if (limit === Infinity) {
            return next(); // Planos infinitos não precisam de verificação
        }

        const startOfMonth = new Date();
        startOfMonth.setDate(1);
        startOfMonth.setHours(0, 0, 0, 0);

        const endOfMonth = new Date(startOfMonth);
        endOfMonth.setMonth(endOfMonth.getMonth() + 1);
        
        const userProjects = await Project.find({ userId: user._id });
        const userProjectIds = userProjects.map(p => p._id);

        const leadsThisMonth = await Lead.countDocuments({
            projectId: { $in: userProjectIds },
            receivedAt: { $gte: startOfMonth, $lt: endOfMonth }
        });

        if (leadsThisMonth >= limit) {
            return res.status(403).json({ message: `Limite de ${limit} leads do plano '${user.plan}' atingido para este mês.` });
        }
        
        next(); // Limite não atingido, pode prosseguir
    } catch (error) {
        console.error('Erro ao verificar o limite de leads:', error);
        res.status(500).json({ message: 'Erro interno no servidor.' });
    }
};

// --- 5. ROTAS DE AUTENTICAÇÃO E USUÁRIOS ---

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email: email });
        if (!user) {
            return res.status(401).json({ message: 'Credenciais inválidas' });
        }
        const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
        if (!isPasswordValid) {
            return res.status(401).json({ message: 'Credenciais inválidas' });
        }
        const token = jwt.sign({ userId: user._id, email: user.email }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ message: 'Login bem-sucedido!', token });
    } catch (error) {
        console.error('Erro no login:', error);
        res.status(500).json({ message: 'Erro interno no servidor' });
    }
});

// A rota de registro agora cria um usuário com o plano padrão 'Free'
app.post('/api/users/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        if (!name || !email || !password) {
            return res.status(400).json({ message: 'Nome, email e senha são obrigatórios.' });
        }
        
        const existingUser = await User.findOne({ email: email });
        if (existingUser) {
            return res.status(409).json({ message: 'Este email já está em uso.' });
        }
        
        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);

        // O Mongoose irá aplicar os valores padrão para 'plan' e 'subscriptionStatus'
        const newUser = new User({ name, email, passwordHash });
        await newUser.save();

        const newProject = new Project({ name: 'Meu Primeiro Projeto', userId: newUser._id });
        await newProject.save();

        res.status(201).json({ message: 'Usuário registrado com sucesso!' });
    } catch (error) {
        console.error('Erro no registro:', error);
        res.status(500).json({ message: 'Erro ao registrar usuário' });
    }
});

app.get('/api/users/me', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId).select('-passwordHash');
        if (!user) {
            return res.status(404).json({ message: 'Usuário não encontrado.' });
        }
        res.json(user);
    } catch (error) {
        console.error('Erro ao buscar usuário:', error);
        res.status(500).json({ message: 'Erro interno no servidor' });
    }
});

// A rota 'me' agora retorna os dados do plano
app.get('/api/users/me', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId).select('-passwordHash');
        if (!user) {
            return res.status(404).json({ message: 'Usuário não encontrado.' });
        }
        res.json(user); // Retorna o objeto completo do usuário, incluindo o plano
    } catch (error) {
        console.error('Erro ao buscar usuário:', error);
        res.status(500).json({ message: 'Erro interno no servidor' });
    }
});

// --- 6. ROTAS DE PROJETOS ---

app.get('/api/projects', authenticateToken, async (req, res) => {
    try {
        const userProjects = await Project.find({ userId: req.user.userId });
        res.json(userProjects);
    } catch (error) {
        console.error('Erro ao buscar projetos:', error);
        res.status(500).json({ message: 'Erro ao buscar projetos' });
    }
});

app.post('/api/projects', authenticateToken, async (req, res) => {
    try {
        const { name } = req.body;
        if (!name || name.trim() === '') {
            return res.status(400).json({ message: 'O nome do projeto é obrigatório.' });
        }
        
        const newProject = new Project({ name, userId: req.user.userId });
        await newProject.save();
        res.status(201).json(newProject);
    } catch (error) {
        console.error('Erro ao criar projeto:', error);
        res.status(500).json({ message: 'Erro ao criar projeto' });
    }
});

app.put('/api/projects/:projectId', authenticateToken, async (req, res) => {
    try {
        const { name } = req.body;
        if (!name || name.trim() === '') {
            return res.status(400).json({ message: 'O nome do projeto é obrigatório.' });
        }

        const updatedProject = await Project.findOneAndUpdate(
            { _id: req.params.projectId, userId: req.user.userId },
            { name: name },
            { new: true }
        );

        if (!updatedProject) {
            return res.status(404).json({ message: 'Projeto não encontrado ou acesso negado.' });
        }
        res.json(updatedProject);
    } catch (error) {
        console.error('Erro ao renomear projeto:', error);
        res.status(500).json({ message: 'Erro ao renomear projeto' });
    }
});


// --- 7. ROTAS DE LEADS ---

// A rota de captura agora usa o novo middleware 'checkLeadLimit'
app.post('/api/capture/:projectId', checkLeadLimit, async (req, res) => {
    try {
        const leadData = req.body;
        if (!leadData.email) return res.status(400).json({ message: 'O campo email é obrigatório.' });
        
        const newLead = new Lead({
            projectId: req.params.projectId,
            nome: leadData.nome,
            email: leadData.email,
            telefone: leadData.telefone,
            cidade: leadData.cidade
        });
        await newLead.save();
        
        res.status(201).json({ message: 'Lead capturado com sucesso!' });
    } catch (error) {
        console.error('Erro ao capturar lead:', error);
        res.status(500).json({ message: 'Erro ao capturar lead' });
    }
});

app.get('/api/leads', authenticateToken, async (req, res) => {
    try {
        const { projectId, page = 1, limit = 10 } = req.query;
        const currentPage = parseInt(page, 10);
        const leadsLimit = parseInt(limit, 10);
        
        const userProjects = await Project.find({ userId: req.user.userId });
        const userProjectIds = userProjects.map(p => p._id);
        
        const leadsQuery = { projectId: { $in: userProjectIds } };
        if (projectId && projectId !== 'all') {
            leadsQuery.projectId = projectId;
        }
        
        const leads = await Lead.find(leadsQuery)
            .sort({ receivedAt: -1 })
            .skip((currentPage - 1) * leadsLimit)
            .limit(leadsLimit);

        const totalLeads = await Lead.countDocuments(leadsQuery);
        const totalPages = Math.ceil(totalLeads / leadsLimit);

        res.json({ leads, currentPage, totalPages, totalLeads });
    } catch (error) {
        console.error('Erro ao buscar leads:', error);
        res.status(500).json({ message: 'Erro ao buscar leads' });
    }
});

app.put('/api/leads/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const updatedData = req.body;
        
        const leadToUpdate = await Lead.findById(id);
        if (!leadToUpdate) {
            return res.status(404).json({ message: 'Lead não encontrado.' });
        }
        
        const project = await Project.findById(leadToUpdate.projectId);
        if (project.userId.toString() !== req.user.userId) {
            return res.status(403).json({ message: 'Acesso negado.' });
        }
        
        leadToUpdate.nome = updatedData.nome || leadToUpdate.nome;
        leadToUpdate.cidade = updatedData.cidade || leadToUpdate.cidade;
        leadToUpdate.status = updatedData.status || leadToUpdate.status;
        
        if (updatedData.novoComentario && updatedData.novoComentario.trim() !== '') {
            leadToUpdate.comentarios.push({ texto: updatedData.novoComentario });
        }
        
        const savedLead = await leadToUpdate.save();
        res.json(savedLead);
    } catch (error) {
        console.error('Erro ao atualizar lead:', error);
        res.status(500).json({ message: 'Erro ao atualizar lead' });
    }
});


// --- 8. ROTA DE ANALYTICS (ATUALIZADA E CORRIGIDA) ---
app.get('/api/analytics', authenticateToken, async (req, res) => {
    try {
        const { projectId } = req.query;
        const user = await User.findById(req.user.userId);
        
        // Determina os projetos a serem analisados (todos do usuário ou um específico)
        const userProjectsQuery = { userId: req.user.userId };
        if (projectId && projectId !== 'all') {
            userProjectsQuery._id = projectId;
        }
        const userProjects = await Project.find(userProjectsQuery);
        const userProjectIds = userProjects.map(p => p._id);
        
        // Busca todos os leads relevantes de uma vez para otimizar
        const relevantLeads = await Lead.find({ projectId: { $in: userProjectIds } });

        // --- Lógica do Gráfico de Pizza (Leads por Projeto) ---
        // Pega todos os projetos do usuário para o gráfico de pizza, independente do filtro
        const allUserProjects = await Project.find({ userId: req.user.userId });
        const allLeads = await Lead.find({ projectId: { $in: allUserProjects.map(p => p._id) } });

        const leadsByProject = allUserProjects.map(project => {
            const count = allLeads.filter(lead => lead.projectId.toString() === project._id.toString()).length;
            return { name: project.name, value: count };
        }).filter(p => p.value > 0); // Mostra apenas projetos com leads

        // --- Lógica do Gráfico de Hoje (Últimas 24 horas) ---
        const now = new Date();
        const twentyFourHoursAgo = new Date(now.getTime() - (24 * 60 * 60 * 1000));
        const recentLeads = relevantLeads.filter(lead => new Date(lead.receivedAt) > twentyFourHoursAgo);
        const hourlyCounts = Array.from({ length: 24 }, (_, i) => ({ hour: i.toString(), leads: 0 }));
        recentLeads.forEach(lead => {
            const leadHour = new Date(lead.receivedAt).getHours();
            if (hourlyCounts[leadHour]) hourlyCounts[leadHour].leads++;
        });

        // --- Lógica para Leads nos Últimos 6 Meses ---
        const sixMonthsAgo = new Date();
        sixMonthsAgo.setMonth(sixMonthsAgo.getMonth() - 6);
        const leadsLast6MonthsData = await Lead.aggregate([
            { $match: { projectId: { $in: userProjectIds }, receivedAt: { $gte: sixMonthsAgo } } },
            { $group: { _id: { month: { $month: "$receivedAt" } }, leads: { $sum: 1 } } },
            { $sort: { "_id.month": 1 } }
        ]);
        const monthMap = ["JAN", "FEV", "MAR", "ABR", "MAI", "JUN", "JUL", "AGO", "SET", "OUT", "NOV", "DEZ"];
        const currentMonthIndex = new Date().getMonth();
        const last6MonthsMap = Array.from({length: 6}, (_, i) => {
            const monthIndex = (currentMonthIndex - 5 + i + 12) % 12;
            return { index: monthIndex + 1, name: monthMap[monthIndex] };
        });

        const leadsLast6Months = last6MonthsMap.map(monthInfo => {
            const monthData = leadsLast6MonthsData.find(item => item._id.month === monthInfo.index);
            return { name: monthInfo.name, leads: monthData ? monthData.leads : 0 };
        });

        // --- NOVA LÓGICA PARA USO MENSAL (CORREÇÃO PRINCIPAL) ---
        const limit = planLimits[user.plan];
        let leadsThisMonth = 0;
        
        const startOfMonth = new Date();
        startOfMonth.setDate(1);
        startOfMonth.setHours(0, 0, 0, 0);

        const endOfMonth = new Date(startOfMonth);
        endOfMonth.setMonth(endOfMonth.getMonth() + 1);
        
        // Conta leads de TODOS os projetos do usuário para o uso mensal
        const allUserProjectIdsForMonth = allUserProjects.map(p => p._id);
        leadsThisMonth = await Lead.countDocuments({
            projectId: { $in: allUserProjectIdsForMonth },
            receivedAt: { $gte: startOfMonth, $lt: endOfMonth }
        });
        
        const monthlyUsagePercent = limit === Infinity ? 0 : Math.floor((leadsThisMonth / limit) * 100);

        // --- ENVIA A RESPOSTA CORRIGIDA ---
        res.json({
            leadsLast6Months: leadsLast6Months,
            leadsLast24Hours: hourlyCounts, // Nome corrigido para refletir a lógica
            leadsByProject: leadsByProject,
            monthlyUsage: {
                current: leadsThisMonth,
                limit: limit,
                percent: Math.min(monthlyUsagePercent, 100)
            }
        });

    } catch (error) {
        console.error('Erro ao buscar analytics:', error);
        res.status(500).json({ message: 'Erro ao buscar analytics' });
    }
});


// ROTA PARA CRIAR A SESSÃO DE CHECKOUT
app.post('/api/stripe/create-checkout-session', authenticateToken, async (req, res) => {
    const { priceId } = req.body;
    const userId = req.user.userId; // Pegamos o ID do usuário do nosso token JWT

    try {
        const session = await stripeInstance.checkout.sessions.create({
            mode: 'subscription',
            payment_method_types: ['card'],
            line_items: [{
                price: priceId,
                quantity: 1,
            }],
            // Importante: Passamos o ID do nosso usuário para identificar no webhook
            client_reference_id: userId,
            success_url: `${process.env.FRONTEND_URL}/`, // Crie essa página no front-end
            cancel_url: `${process.env.FRONTEND_URL}/plans`, // Página de planos
        });

        res.json({ url: session.url });
    } catch (error) {
        console.error('Erro ao criar sessão de checkout:', error);
        res.status(500).json({ error: 'Não foi possível iniciar o checkout.' });
    }
});

app.post('/api/stripe/create-portal-session', authenticateToken, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId);
        if (!user || !user.stripeCustomerId) {
            return res.status(400).json({ message: 'Usuário não encontrado ou sem assinatura.' });
        }

        const portalSession = await stripeInstance.billingPortal.sessions.create({
            customer: user.stripeCustomerId,
            return_url: `${process.env.FRONTEND_URL}/plans`,
        });

        res.json({ url: portalSession.url });
    } catch (error) {
        console.error('Erro ao criar sessão do portal do cliente:', error);
        res.status(500).json({ error: 'Não foi possível acessar o portal de gerenciamento.' });
    }
});


// --- 9. INICIA O SERVIDOR ---
app.listen(PORT, () => {
  console.log(`🚀 Servidor back-end rodando em http://localhost:${PORT}`);
});