<?php

namespace App\Controller;

use App\Entity\User;
use App\Repository\UserRepository;
use App\Services\Avatar;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\File\UploadedFile;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Http\Attribute\CurrentUser;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;

class UserController extends AbstractController
{
    private const ALLOWED_IMAGE_EXTENSIONS = ['png', 'jpg', 'jpeg', 'gif'];

    private function validateCsrf(Request $request, CsrfTokenManagerInterface $csrfTokenManager, string $id): bool
    {
        $token = new CsrfToken($id, (string) $request->request->get('_token'));
        return $csrfTokenManager->isTokenValid($token);
    }

    private function isAllowedUrl(string $url): bool
    {
        if (!filter_var($url, FILTER_VALIDATE_URL)) {
            return false;
        }

        $parts = parse_url($url);
        if (!isset($parts['scheme'], $parts['host']) || !in_array($parts['scheme'], ['http', 'https'], true)) {
            return false;
        }

        $host = $parts['host'];
        if (in_array($host, ['localhost', '127.0.0.1', '::1'], true)) {
            return false;
        }

        $ip = gethostbyname($host);
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
            return false;
        }

        return true;
    }

    #[Route('/user', name: 'app_user')]
    public function index(
        #[CurrentUser] ?User $user,
    ): Response
    {
        return $this->render('user/index.html.twig', [
            'user' => $user,
        ]);
    }

    #[Route('/user/password/{user}', name: 'app_user_password', methods: ['POST'])]
    public function changePassword(
        User $user,
        Request $request,
        UserRepository $userRepository,
        UserPasswordHasherInterface $passwordHasher,
        CsrfTokenManagerInterface $csrfTokenManager
    ): Response {
        if ($user !== $this->getUser()) {
            throw $this->createAccessDeniedException('You cannot change another user password');
        }

        if (!$this->validateCsrf($request, $csrfTokenManager, 'user_password_'.$user->getId())) {
            $this->addFlash('error', 'Invalid CSRF token');
            return $this->redirectToRoute('app_user');
        }

        $password = (string) $request->get('newPassword');
        $confirmPassword = (string) $request->get('confirmPassword');

        if ($password !== $confirmPassword) {
            $this->addFlash('error', 'Passwords do not match');
            return $this->redirectToRoute('app_user');
        }

        if (strlen($password) < 8) {
            $this->addFlash('error', 'Password must be at least 8 characters');
            return $this->redirectToRoute('app_user');
        }

        $hashed = $passwordHasher->hashPassword($user, $password);
        $user->setPassword($hashed);

        $userRepository->save($user, true);

        $this->addFlash('success', 'Password changed successfully');
        return $this->redirectToRoute('app_user');
    }

    #[Route('/user/email/{user}', name: 'app_user_email', methods: ['POST'])]
    public function changeEmail(
        User $user,
        Request $request,
        UserRepository $userRepository,
        CsrfTokenManagerInterface $csrfTokenManager
    ): Response {
        if ($user !== $this->getUser()) {
            throw $this->createAccessDeniedException('You cannot change another user email');
        }

        if (!$this->validateCsrf($request, $csrfTokenManager, 'user_email_'.$user->getId())) {
            $this->addFlash('error', 'Invalid CSRF token');
            return $this->redirectToRoute('app_user');
        }

        $email = (string) $request->get('newEmail');

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $this->addFlash('error', 'Email is not valid');
            return $this->redirectToRoute('app_user');
        }

        if ($existing = $userRepository->findOneBy(['email' => $email])) {
            if ($existing->getId() !== $user->getId()) {
                $this->addFlash('error', 'Email already in use');
                return $this->redirectToRoute('app_user');
            }
        }

        $user->setEmail($email);
        $userRepository->save($user, true);

        $this->addFlash('success', 'Email changed successfully');
        return $this->redirectToRoute('app_user');
    }

    #[Route('/user/avatar/{user}', name: 'app_user_avatar', methods: ['POST'])]
    public function uploadAvatar(
        Request $request,
        UserRepository $userRepository,
        User $user,
        CsrfTokenManagerInterface $csrfTokenManager
    ): Response {
        if ($user !== $this->getUser()) {
            $this->addFlash('error', 'You cannot change other users avatar');
            return $this->redirectToRoute('app_user');
        }

        if (!$this->validateCsrf($request, $csrfTokenManager, 'user_avatar_'.$user->getId())) {
            $this->addFlash('error', 'Invalid CSRF token');
            return $this->redirectToRoute('app_user');
        }

        /** @var UploadedFile|null $avatar */
        $avatar = $request->files->get('avatar');

        if (!$avatar) {
            $this->addFlash('error', 'Avatar cannot be empty');
            return $this->redirectToRoute('app_user');
        }

        $extension = strtolower((string) $avatar->guessExtension());
        $mimeType = (string) $avatar->getMimeType();
        if (!in_array($extension, self::ALLOWED_IMAGE_EXTENSIONS, true)) {
            $this->addFlash('error', 'Invalid file type');
            return $this->redirectToRoute('app_user');
        }
        if (!str_starts_with($mimeType, 'image/')) {
            $this->addFlash('error', 'Invalid image content');
            return $this->redirectToRoute('app_user');
        }

        // If the avatar file already exists, delete it
        $avatarPath = $this->getParameter('avatars_directory') . '/' . $user->getAvatar();
        if (!empty($user->getAvatar()) && is_file($avatarPath)) {
            unlink($avatarPath);
        }

        // If the avatar directory does not exist, create it
        if (!is_dir($this->getParameter('avatars_directory'))) {
            mkdir($this->getParameter('avatars_directory'), 0755, true);
        }

        $avatarName = md5(uniqid((string) $user->getId(), true)) . '.' . $extension;
        $avatar->move($this->getParameter('avatars_directory'), $avatarName);

        $user->setAvatar($avatarName);
        $userRepository->save($user, true);

        $this->addFlash('success', 'Avatar changed successfully');
        return $this->redirectToRoute('app_user');
    }

    #[Route('/user/avatar/url/{user}', name: 'app_user_url_avatar', methods: ['POST'])]
    public function getAvatarFromUrl(
        Request $request,
        UserRepository $userRepository,
        User $user,
        Avatar $avatarService,
        CsrfTokenManagerInterface $csrfTokenManager
    ): Response {
        if ($user !== $this->getUser()) {
            $this->addFlash('error', 'You cannot change other users avatar');
            return $this->redirectToRoute('app_user');
        }

        if (!$this->validateCsrf($request, $csrfTokenManager, 'user_avatar_url_'.$user->getId())) {
            $this->addFlash('error', 'Invalid CSRF token');
            return $this->redirectToRoute('app_user');
        }

        $url = (string) $request->get('url');

        if (!$this->isAllowedUrl($url)) {
            $this->addFlash('error', 'URL is not allowed');
            return $this->redirectToRoute('app_user');
        }

        $content = $avatarService->getFromUrl($url);

        if ($content === false) {
            $this->addFlash('error', 'URL is not valid or cannot be reached');
            return $this->redirectToRoute('app_user');
        }

        $imageInfo = @getimagesizefromstring($content);
        if ($imageInfo === false) {
            $this->addFlash('error', 'Content is not a valid image');
            return $this->redirectToRoute('app_user');
        }

        $extension = image_type_to_extension($imageInfo[2], false);
        if (!in_array($extension, self::ALLOWED_IMAGE_EXTENSIONS, true)) {
            $this->addFlash('error', 'Image format not allowed');
            return $this->redirectToRoute('app_user');
        }

        if (!is_dir($this->getParameter('avatars_directory'))) {
            mkdir($this->getParameter('avatars_directory'), 0755, true);
        }

        $avatarName = md5(uniqid((string) $user->getId(), true)) . '.' . $extension;
        file_put_contents($this->getParameter('avatars_directory') . '/' . $avatarName, $content);

        $user->setAvatar($avatarName);
        $userRepository->save($user, true);

        $this->addFlash('success', 'Avatar changed successfully');
        return $this->redirectToRoute('app_user');
    }

    #[Route('/user/avatar/delete/{user}', name: 'app_user_avatar_delete', methods: ['POST'])]
    public function deleteAvatar(
        User $user,
        UserRepository $userRepository,
        Request $request,
        CsrfTokenManagerInterface $csrfTokenManager
    ): Response {
        if ($user !== $this->getUser()) {
            $this->addFlash('error', 'You cannot change other users avatar');
            return $this->redirectToRoute('app_user');
        }

        if (!$this->validateCsrf($request, $csrfTokenManager, 'user_avatar_delete_'.$user->getId())) {
            $this->addFlash('error', 'Invalid CSRF token');
            return $this->redirectToRoute('app_user');
        }

        if (empty($user->getAvatar())) {
            $this->addFlash('error', 'No avatar to delete');
            return $this->redirectToRoute('app_user');
        }

        $path = $this->getParameter('avatars_directory') . '/' . $user->getAvatar();
        if (is_file($path)) {
            unlink($path);
        }

        $user->setAvatar(null);
        $userRepository->save($user, true);

        $this->addFlash('success', 'Avatar deleted successfully');
        return $this->redirectToRoute('app_user');
    }

    #[Route('/user/avatar/resize/{user}', name: 'app_user_avatar_resize', methods: ['POST'])]
    public function resizeAvatar(
        User $user,
        Request $request,
        CsrfTokenManagerInterface $csrfTokenManager
    ): Response {
        if ($user !== $this->getUser()) {
            $this->addFlash('error', 'You cannot change other users avatar');
            return $this->redirectToRoute('app_user');
        }

        if (!$this->validateCsrf($request, $csrfTokenManager, 'user_avatar_resize_'.$user->getId())) {
            $this->addFlash('error', 'Invalid CSRF token');
            return $this->redirectToRoute('app_user');
        }

        $avatar = $user->getAvatar();

        if (empty($avatar)) {
            $this->addFlash('error', 'No avatar to resize');
            return $this->redirectToRoute('app_user');
        }

        $avatarFile = $this->getParameter('avatars_directory') . '/' . $avatar;
        if (!is_file($avatarFile)) {
            $this->addFlash('error', 'Avatar file missing');
            return $this->redirectToRoute('app_user');
        }

        $imageInfo = getimagesize($avatarFile);
        if ($imageInfo === false) {
            $this->addFlash('error', 'Avatar is not a valid image');
            return $this->redirectToRoute('app_user');
        }

        [$width, $height, $type] = $imageInfo;
        switch ($type) {
            case IMAGETYPE_JPEG:
                $source = imagecreatefromjpeg($avatarFile);
                $saveFn = static fn($res, $path) => imagejpeg($res, $path, 90);
                break;
            case IMAGETYPE_PNG:
                $source = imagecreatefrompng($avatarFile);
                $saveFn = static fn($res, $path) => imagepng($res, $path, 6);
                break;
            case IMAGETYPE_GIF:
                $source = imagecreatefromgif($avatarFile);
                $saveFn = static fn($res, $path) => imagegif($res, $path);
                break;
            default:
                $this->addFlash('error', 'Unsupported image format');
                return $this->redirectToRoute('app_user');
        }

        $destination = imagecreatetruecolor(200, 200);
        imagecopyresampled($destination, $source, 0, 0, 0, 0, 200, 200, $width, $height);
        $saveFn($destination, $avatarFile);
        imagedestroy($source);
        imagedestroy($destination);

        $this->addFlash('success', 'Avatar resized successfully');
        return $this->redirectToRoute('app_user');
    }

    #[Route('/user/about/', name: 'app_user_about', methods: ['POST'])]
    public function about(
        Request $request,
        EntityManagerInterface $entityManager,
        #[CurrentUser] ?User $user,
        CsrfTokenManagerInterface $csrfTokenManager
    ): Response
    {
        if (!$user) {
            return $this->redirectToRoute('app_login');
        }

        if (!$this->validateCsrf($request, $csrfTokenManager, 'user_about_'.$user->getId())) {
            $this->addFlash('error', 'Invalid CSRF token');
            return $this->redirectToRoute('app_user');
        }

        $about = strip_tags((string) $request->get('about'));
        $user->setAboutMe($about);
        $entityManager->flush();

        $this->addFlash('success', 'About changed successfully');
        return $this->redirectToRoute('app_user');
    }

    #[Route('/user/edit/', name: 'app_user_edit_form', methods: ['GET'])]
    public function editForm(
        #[CurrentUser] ?User $user,
    ): Response
    {
        return $this->render('user/edit.html.twig', ['user' => $user]);
    }

    #[Route('/user/edit/', name: 'app_user_edit', methods: ['POST'])]
    public function edit(
        Request $request,
        EntityManagerInterface $entityManager,
        #[CurrentUser] ?User $user,
        CsrfTokenManagerInterface $csrfTokenManager
    ): Response
    {
        if (!$user) {
            return $this->redirectToRoute('app_login');
        }

        if (!$this->validateCsrf($request, $csrfTokenManager, 'user_edit_'.$user->getId())) {
            $this->addFlash('error', 'Invalid CSRF token');
            return $this->redirectToRoute('app_user');
        }

        $firstname = trim((string) $request->request->get('firstname'));
        $lastname = trim((string) $request->request->get('lastname'));

        $user->setFirstname($firstname);
        $user->setLastname($lastname);

        $entityManager->flush();

        $this->addFlash('success', 'User changed successfully');
        return $this->redirectToRoute('app_user');
    }

}
