import type {Config} from 'jest';

const config: Config = {
    verbose: true,
    preset: 'ts-jest',
    testEnvironment: 'jsdom',
    setupFilesAfterEnv: ['@testing-library/jest-dom/extend-expect', '<rootDir>/src/setupTests.ts'],
    moduleNameMapper: {
        // '\\.(css|less|scss|sass)$': 'identity-obj-proxy',
        '^axios$': require.resolve('axios'),
    },
    moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx', 'json', 'node'],
    testPathIgnorePatterns: ['/node_modules', 'dist/'],
    // testPathIgnorePatterns: ['/node_modules/', '/dist/', 'node_modules/(?!axios/.*)'],
    globals: {
        'ts-jest': {
            tsconfig: 'tsconfig.json',
            useESM:  true,
        },
    },
    transform: {
        '^.+\\.(js|jsx|ts|tsx)$': 'ts-jest',
        "node_modules/axios/.+\\.(j|t)sx?$": "ts-jest",
        "src/api/apiClient.ts": 'ts-jest',
        "^.+\\.(ts|tsx|js|jsx)$": "ts-jest",
        '^.+\\.ts?$': 'ts-jest',
    },
    transformIgnorePatterns: [
        '/node_modules/(?!axios)/',
        'node_modules/(?!axios)/',
    ],
};

export default config;
