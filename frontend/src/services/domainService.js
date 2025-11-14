import apiClient, { API_ENDPOINTS } from "../config/api";

const fetchVerificationProfile = async () => {
    const response = await apiClient.get(API_ENDPOINTS.verification.profile);
    return response.data;
};

const createDomain = async (domain) => {
    const response = await apiClient.post(API_ENDPOINTS.verification.create, {
        domain,
    });
    return response.data;
};

const deleteDomain = async (id) => {
    await apiClient.delete(API_ENDPOINTS.verification.item(id));
};

const verifyDomain = async (id) => {
    const response = await apiClient.post(API_ENDPOINTS.verification.verify(id));
    return response.data;
};

const rotateVerificationToken = async () => {
    const response = await apiClient.post(API_ENDPOINTS.verification.rotateToken);
    return response.data;
};

const domainService = {
    fetchVerificationProfile,
    createDomain,
    deleteDomain,
    verifyDomain,
    rotateVerificationToken,
};

export default domainService;

