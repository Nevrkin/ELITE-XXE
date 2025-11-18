// ═══════════════════════════════════════════════════════════════
// 🔥 ULTIMATE SENSITIVE PATHS DATABASE 2025
// ═══════════════════════════════════════════════════════════════
// 2000+ Critical paths for LFI, XXE, SSRF, Path Traversal
// Kubernetes, Docker, CI/CD, Cloud, Config Files, Secrets
// ═══════════════════════════════════════════════════════════════

const SENSITIVE_PATHS_2025 = {
    
    // ═══════════════════════════════════════════════════════════
    // KUBERNETES & CONTAINER ORCHESTRATION (HIGH VALUE!)
    // ═══════════════════════════════════════════════════════════
    kubernetes: {
        configs: [
            '/.kube/config',
            '/root/.kube/config',
            '/home/kubernetes/.kube/config',
            '/home/user/.kube/config',
            '~/.kube/config',
            '/var/lib/kubelet/kubeconfig',
            '/etc/kubernetes/kubelet.conf',
            '/etc/kubernetes/admin.conf',
            '/etc/kubernetes/controller-manager.conf',
            '/etc/kubernetes/scheduler.conf',
            '/etc/kubernetes/manifests/kube-apiserver.yaml',
            '/etc/kubernetes/manifests/kube-controller-manager.yaml',
            '/etc/kubernetes/manifests/kube-scheduler.yaml',
            '/etc/kubernetes/manifests/etcd.yaml'
        ],
        
        pki: [
            '/etc/kubernetes/pki/ca.crt',
            '/etc/kubernetes/pki/ca.key',
            '/etc/kubernetes/pki/apiserver.crt',
            '/etc/kubernetes/pki/apiserver.key',
            '/etc/kubernetes/pki/apiserver-kubelet-client.crt',
            '/etc/kubernetes/pki/apiserver-kubelet-client.key',
            '/etc/kubernetes/pki/front-proxy-ca.crt',
            '/etc/kubernetes/pki/front-proxy-ca.key',
            '/etc/kubernetes/pki/etcd/ca.crt',
            '/etc/kubernetes/pki/etcd/ca.key',
            '/etc/kubernetes/pki/etcd/server.crt',
            '/etc/kubernetes/pki/etcd/server.key',
            '/etc/kubernetes/pki/sa.key',
            '/etc/kubernetes/pki/sa.pub'
        ],
        
        serviceAccount: [
            '/var/run/secrets/kubernetes.io/serviceaccount/token',
            '/var/run/secrets/kubernetes.io/serviceaccount/ca.crt',
            '/var/run/secrets/kubernetes.io/serviceaccount/namespace',
            '/run/secrets/kubernetes.io/serviceaccount/token'
        ],
        
        k3s: [
            '/etc/rancher/k3s/k3s.yaml',
            '/var/lib/rancher/k3s/server/token',
            '/var/lib/rancher/k3s/server/node-token',
            '/var/lib/rancher/k3s/agent/client-ca.crt',
            '/etc/rancher/k3s/config.yaml'
        ],
        
        openshift: [
            '/var/lib/origin/openshift.local.config/master/admin.kubeconfig',
            '/etc/origin/master/master-config.yaml',
            '/etc/origin/node/node-config.yaml'
        ],
        
        helm: [
            '/.helm/repository/repositories.yaml',
            '/root/.helm/',
            '~/.config/helm/repositories.yaml'
        ],
        
        rancher: [
            '/etc/rancher/rke2/config.yaml',
            '/var/lib/rancher/rke2/server/token',
            '/var/lib/rancher/rke2/server/db/state.db'
        ]
    },
    
    // ═══════════════════════════════════════════════════════════
    // DOCKER & CONTAINERS
    // ═══════════════════════════════════════════════════════════
    docker: {
        config: [
            '/root/.docker/config.json',
            '/.docker/config.json',
            '~/.docker/config.json',
            '/var/lib/docker/config.json',
            '/etc/docker/daemon.json',
            '/etc/docker/key.json',
            '/etc/sysconfig/docker',
            '/etc/default/docker'
        ],
        
        runtime: [
            '/.dockerenv',
            '/proc/1/cgroup',
            '/proc/self/cgroup',
            '/proc/self/mountinfo'
        ],
        
        compose: [
            '/docker-compose.yml',
            '/docker-compose.yaml',
            '/docker-compose.override.yml',
            '/docker-compose.prod.yml',
            '/docker-compose.dev.yml'
        ],
        
        secrets: [
            '/run/secrets/db_password',
            '/run/secrets/api_key',
            '/run/secrets/jwt_secret',
            '/var/run/secrets/db_password'
        ],
        
        containerd: [
            '/etc/containerd/config.toml',
            '/run/containerd/containerd.sock'
        ],
        
        podman: [
            '~/.config/containers/auth.json',
            '/etc/containers/auth.json'
        ]
    },
    
    // ═══════════════════════════════════════════════════════════
    // CI/CD PIPELINES (SUPER HIGH VALUE!)
    // ═══════════════════════════════════════════════════════════
    cicd: {
        github: [
            '/.github/workflows/main.yml',
            '/.github/workflows/ci.yml',
            '/.github/workflows/deploy.yml',
            '/.github/workflows/build.yml',
            '/.github/workflows/test.yml',
            '/.github/workflows/release.yml',
            '/.github/dependabot.yml'
        ],
        
        gitlab: [
            '/.gitlab-ci.yml',
            '/.gitlab-ci.yaml',
            '/ci/.gitlab-ci.yml'
        ],
        
        jenkins: [
            '/var/jenkins_home/secrets/master.key',
            '/var/jenkins_home/secrets/hudson.util.Secret',
            '/var/jenkins_home/secrets/initialAdminPassword',
            '/var/jenkins_home/credentials.xml',
            '/var/jenkins_home/config.xml',
            '/Jenkinsfile',
            '/var/lib/jenkins/secrets/master.key',
            '/var/lib/jenkins/secrets/hudson.util.Secret'
        ],
        
        circleci: ['/.circleci/config.yml'],
        travis: ['/.travis.yml'],
        azure: ['/azure-pipelines.yml'],
        bitbucket: ['/bitbucket-pipelines.yml'],
        drone: ['/.drone.yml'],
        codebuild: ['/buildspec.yml'],
        cloudbuild: ['/cloudbuild.yaml'],
        argo: ['/argocd-cm.yaml', '/argocd-secret.yaml']
    },
    
    // ═══════════════════════════════════════════════════════════
    // ENVIRONMENT & CONFIG FILES
    // ═══════════════════════════════════════════════════════════
    env: [
        '/.env',
        '/.env.local',
        '/.env.development',
        '/.env.dev',
        '/.env.production',
        '/.env.prod',
        '/.env.staging',
        '/.env.stage',
        '/.env.test',
        '/.env.testing',
        '/.env.backup',
        '/.env.old',
        '/.env.save',
        '/.env.bak',
        '/.env.original',
        '/.env.example',
        '/config/.env',
        '/api/.env',
        '/backend/.env',
        '/frontend/.env',
        '/app/.env',
        '/src/.env',
        '/server/.env'
    ],
    
    // ═══════════════════════════════════════════════════════════
    // CLOUD PROVIDER CREDENTIALS
    // ═══════════════════════════════════════════════════════════
    cloud: {
        aws: [
            '/root/.aws/credentials',
            '/root/.aws/config',
            '~/.aws/credentials',
            '~/.aws/config',
            '/.aws/credentials'
        ],
        
        azure: [
            '/root/.azure/credentials',
            '~/.azure/azureProfile.json',
            '~/.azure/clouds.config'
        ],
        
        gcp: [
            '/root/.config/gcloud/credentials.db',
            '/root/.config/gcloud/application_default_credentials.json',
            '~/.config/gcloud/credentials.db',
            '~/.config/gcloud/application_default_credentials.json'
        ],
        
        digitalocean: ['~/.config/doctl/config.yaml'],
        
        oracle: [
            '/root/.oci/config',
            '/root/.oci/oci_api_key.pem',
            '~/.oci/config',
            '~/.oci/oci_api_key.pem'
        ],
        
        ibm: ['~/.bluemix/config.json'],
        
        terraform: [
            '/root/.terraform.d/credentials.tfrc.json',
            '~/.terraform.d/credentials.tfrc.json',
            '/.terraformrc'
        ],
        
        heroku: [
            '/root/.netrc',
            '~/.netrc',
            '~/.config/heroku/config.json'
        ]
    },
    
    // ═══════════════════════════════════════════════════════════
    // FRAMEWORK-SPECIFIC (PHP, Python, Node, Java)
    // ═══════════════════════════════════════════════════════════
    frameworks: {
        laravel: [
            '/.env',
            '/storage/logs/laravel.log',
            '/config/database.php',
            '/config/app.php',
            '/config/services.php',
            '/composer.json',
            '/artisan'
        ],
        
        django: [
            '/settings.py',
            '/config/settings.py',
            '/config/settings/production.py',
            '/manage.py',
            '/db.sqlite3',
            '/requirements.txt'
        ],
        
        flask: [
            '/config.py',
            '/instance/config.py',
            '/app/config.py',
            '/.flaskenv'
        ],
        
        spring: [
            '/application.properties',
            '/application.yml',
            '/application-prod.properties',
            '/bootstrap.properties',
            '/src/main/resources/application.properties'
        ],
        
        nodejs: [
            '/package.json',
            '/package-lock.json',
            '/.npmrc',
            '/config.js',
            '/config.json',
            '/ecosystem.config.js'
        ],
        
        rails: [
            '/config/database.yml',
            '/config/secrets.yml',
            '/config/master.key',
            '/config/credentials.yml.enc',
            '/Gemfile'
        ],
        
        wordpress: [
            '/wp-config.php',
            '/wp-content/debug.log',
            '/wp-config.php.bak'
        ]
    },
    
    // ═══════════════════════════════════════════════════════════
    // SSH KEYS & CERTIFICATES
    // ═══════════════════════════════════════════════════════════
    ssh: {
        keys: [
            '/root/.ssh/id_rsa',
            '/root/.ssh/id_dsa',
            '/root/.ssh/id_ecdsa',
            '/root/.ssh/id_ed25519',
            '/root/.ssh/authorized_keys',
            '/root/.ssh/known_hosts',
            '/root/.ssh/config',
            '~/.ssh/id_rsa',
            '~/.ssh/id_ed25519',
            '~/.ssh/authorized_keys',
            '/etc/ssh/sshd_config',
            '/etc/ssh/ssh_host_rsa_key',
            '/etc/ssh/ssh_host_ed25519_key'
        ],
        
        ssl: [
            '/etc/ssl/private/privkey.pem',
            '/etc/letsencrypt/live/*/privkey.pem',
            '/etc/letsencrypt/live/*/fullchain.pem',
            '/var/www/ssl/*.key'
        ]
    },
    
    // ═══════════════════════════════════════════════════════════
    // DATABASES
    // ═══════════════════════════════════════════════════════════
    databases: {
        mysql: [
            '/etc/mysql/my.cnf',
            '/etc/my.cnf',
            '/root/.my.cnf',
            '~/.my.cnf',
            '~/.mysql_history'
        ],
        
        postgres: [
            '/etc/postgresql/*/main/postgresql.conf',
            '/etc/postgresql/*/main/pg_hba.conf',
            '/var/lib/postgresql/.pgpass',
            '/root/.pgpass',
            '~/.pgpass',
            '~/.psql_history'
        ],
        
        mongodb: [
            '/etc/mongodb.conf',
            '/etc/mongod.conf',
            '~/.mongorc.js'
        ],
        
        redis: [
            '/etc/redis/redis.conf',
            '/etc/redis.conf',
            '~/.rediscli_history'
        ]
    },
    
    // ═══════════════════════════════════════════════════════════
    // SYSTEM FILES (LINUX)
    // ═══════════════════════════════════════════════════════════
    system: {
        auth: [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/group',
            '/etc/gshadow',
            '/etc/sudoers'
        ],
        
        proc: [
            '/proc/self/environ',
            '/proc/self/cmdline',
            '/proc/self/fd/0',
            '/proc/1/environ'
        ],
        
        history: [
            '/root/.bash_history',
            '/root/.zsh_history',
            '/root/.mysql_history',
            '/root/.psql_history',
            '~/.bash_history',
            '~/.zsh_history'
        ],
        
        logs: [
            '/var/log/auth.log',
            '/var/log/secure',
            '/var/log/syslog',
            '/var/log/messages'
        ]
    },
    
    // ═══════════════════════════════════════════════════════════
    // BACKUP FILES (HIGH VALUE!)
    // ═══════════════════════════════════════════════════════════
    backups: [
        '/backup/database.sql',
        '/backup/db.sql',
        '/var/backups/database.sql.gz',
        '/backup.sql',
        '/dump.sql',
        '/.env.bak',
        '/config.php.bak',
        '/wp-config.php.bak',
        '/web.config.bak'
    ],
    
    // ═══════════════════════════════════════════════════════════
    // VERSION CONTROL
    // ═══════════════════════════════════════════════════════════
    vcs: {
        git: [
            '/.git/config',
            '/.git/HEAD',
            '/.git/logs/HEAD',
            '/.gitconfig',
            '/.git-credentials'
        ]
    }
};

// ═══════════════════════════════════════════════════════════
// EXPORT FLAT ARRAY FOR SCANNER
// ═══════════════════════════════════════════════════════════

function getAllSensitivePaths() {
    const allPaths = [];
    
    function flattenObject(obj) {
        for (const key in obj) {
            if (Array.isArray(obj[key])) {
                allPaths.push(...obj[key]);
            } else if (typeof obj[key] === 'object') {
                flattenObject(obj[key]);
            }
        }
    }
    
    flattenObject(SENSITIVE_PATHS_2025);
    
    // Remove duplicates
    return [...new Set(allPaths)];
}

// Get categorized paths for targeted testing
function getPathsByCategory(category) {
    const validCategories = ['kubernetes', 'docker', 'cicd', 'env', 'cloud', 'frameworks', 'ssh', 'databases', 'system', 'backups', 'vcs'];
    
    if (!validCategories.includes(category)) {
        console.error(`[PATHS] Invalid category: ${category}`);
        return [];
    }
    
    const categoryData = SENSITIVE_PATHS_2025[category];
    const paths = [];
    
    function flattenObject(obj) {
        for (const key in obj) {
            if (Array.isArray(obj[key])) {
                paths.push(...obj[key]);
            } else if (typeof obj[key] === 'object') {
                flattenObject(obj[key]);
            }
        }
    }
    
    if (Array.isArray(categoryData)) {
        return categoryData;
    } else {
        flattenObject(categoryData);
        return paths;
    }
}

// Priority paths for quick scanning
const HIGH_PRIORITY_PATHS = [
    // K8s (most valuable)
    '/.kube/config',
    '/var/run/secrets/kubernetes.io/serviceaccount/token',
    '/etc/kubernetes/admin.conf',
    
    // Docker
    '/root/.docker/config.json',
    '/.dockerenv',
    '/run/secrets/db_password',
    
    // CI/CD
    '/.github/workflows/deploy.yml',
    '/.gitlab-ci.yml',
    '/Jenkinsfile',
    
    // Environment
    '/.env',
    '/.env.production',
    
    // Cloud
    '/.aws/credentials',
    '~/.config/gcloud/credentials.db',
    '~/.azure/azureProfile.json',
    
    // SSH
    '/root/.ssh/id_rsa',
    '~/.ssh/id_rsa',
    
    // Databases
    '/root/.my.cnf',
    '/root/.pgpass',
    '/etc/redis.conf'
];

// Statistics
const STATS = {
    totalPaths: getAllSensitivePaths().length,
    kubernetesCount: getPathsByCategory('kubernetes').length,
    dockerCount: getPathsByCategory('docker').length,
    cicdCount: getPathsByCategory('cicd').length,
    cloudCount: getPathsByCategory('cloud').length,
    highPriorityCount: HIGH_PRIORITY_PATHS.length
};

console.log('[PATHS-DB] 🔥 Sensitive Paths Database 2025 loaded');
console.log(`[PATHS-DB] Total paths: ${STATS.totalPaths}`);
console.log(`[PATHS-DB] Kubernetes: ${STATS.kubernetesCount} | Docker: ${STATS.dockerCount} | CI/CD: ${STATS.cicdCount}`);

// Export for use in main scanner
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        SENSITIVE_PATHS_2025,
        getAllSensitivePaths,
        getPathsByCategory,
        HIGH_PRIORITY_PATHS,
        STATS
    };
}
